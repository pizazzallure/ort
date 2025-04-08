/*
 * Copyright (C) 2017 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.plugins.packagemanagers.node.npm

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.apache.commons.lang3.StringUtils
import org.apache.logging.log4j.kotlin.logger
import org.ossreviewtoolkit.analyzer.PackageManagerFactory
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.ProjectAnalyzerResult
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.utils.DependencyGraphBuilder
import org.ossreviewtoolkit.plugins.api.OrtPlugin
import org.ossreviewtoolkit.plugins.api.OrtPluginOption
import org.ossreviewtoolkit.plugins.api.PluginDescriptor
import org.ossreviewtoolkit.plugins.packagemanagers.node.*
import org.ossreviewtoolkit.plugins.packagemanagers.node.yarn.WorkspacePackage
import org.ossreviewtoolkit.utils.common.*
import org.ossreviewtoolkit.utils.ort.runBlocking
import org.semver4j.RangesList
import org.semver4j.RangesListFactory
import java.io.File
import java.util.*
import kotlin.io.path.invariantSeparatorsPathString

internal object NpmCommand : CommandLineTool {
    override fun command(workingDir: File?) = if (Os.isWindows) "npm.cmd" else "npm"

    override fun getVersionRequirement(): RangesList = RangesListFactory.create("6.* - 10.*")
}

data class NpmConfig(
    /**
     * If true, the "--legacy-peer-deps" flag is passed to NPM to ignore conflicts in peer dependencies which are
     * reported since NPM 7. This allows to analyze NPM 6 projects with peer dependency conflicts. For more information
     * see the [documentation](https://docs.npmjs.com/cli/v8/commands/npm-install#strict-peer-deps) and the
     * [NPM Blog](https://blog.npmjs.org/post/626173315965468672/npm-v7-series-beta-release-and-semver-major).
     */
    @OrtPluginOption(defaultValue = "false")
    val legacyPeerDeps: Boolean
)

/**
 * The [Node package manager](https://www.npmjs.com/) for JavaScript.
 */
@OrtPlugin(
    id = "NPM",
    displayName = "NPM",
    description = "The Node package manager for Node.js.",
    factory = PackageManagerFactory::class
)
class Npm(override val descriptor: PluginDescriptor = NpmFactory.descriptor, private val config: NpmConfig) :
    NodePackageManager(NodePackageManagerType.NPM) {

    override val globsForDefinitionFiles = listOf(NodePackageManagerType.DEFINITION_FILE)

    private lateinit var stash: NpmDirectoryStash

    private val npmViewCache = mutableMapOf<String, PackageJson>()
    private val handler = NpmDependencyHandler(projectType, this::getRemotePackageDetails)

    override val graphBuilder by lazy { DependencyGraphBuilder(handler) }

    override fun beforeResolution(
        analysisRoot: File,
        definitionFiles: List<File>,
        analyzerConfig: AnalyzerConfiguration
    ) {
        NpmCommand.checkVersion()

        val directories = definitionFiles.mapTo(mutableSetOf()) { it.resolveSibling("node_modules") }
        stash = NpmDirectoryStash(directories)

        // sort the definition files list by the workspace.
        // the sorting can make sure that the project which contains workspaces configuration will be processed first,
        // the workspace packages can be positioned from the symbol link folder inside the node_modules dir of parent project.
        sortByWorkspaces(definitionFiles)
    }

    override fun afterResolution(analysisRoot: File, definitionFiles: List<File>) {
        // clean up after resolve all definition files
        handler.workspacePackagesCache.clear()

        stash.close()
    }

    override fun resolveDependencies(
        analysisRoot: File,
        definitionFile: File,
        excludes: Excludes,
        analyzerConfig: AnalyzerConfiguration,
        labels: Map<String, String>
    ): List<ProjectAnalyzerResult> {
        val workingDir = definitionFile.parentFile
        val issues = installDependencies(analysisRoot, workingDir, analyzerConfig.allowDynamicVersions).toMutableList()

        if (issues.any { it.severity == Severity.ERROR }) {
            val project = runCatching {
                parseProject(definitionFile, analysisRoot)
            }.getOrElse {
                logger.error { "Failed to parse project information: ${it.collectMessages()}" }
                Project.EMPTY
            }

            return listOf(ProjectAnalyzerResult(project, emptySet(), issues))
        }

        val project = parseProject(definitionFile, analysisRoot)
        var packageNameWithNamespace =
            if (StringUtils.isNotEmpty(project.id.namespace)) project.id.namespace + "/" + project.id.name else project.id.name
        val workspacePackage = handler.workspacePackagesCache.firstOrNull { workspacePackage ->
            workspacePackage.workspaceName.equals(packageNameWithNamespace)
        }
        val dependencyToType = listDependenciesByType(definitionFile)
        val projectModuleInfo =
            listModules(
                workingDir,
                issues,
                project,
                workspacePackage != null,
                dependencyToType,
                analysisRoot,
                excludes
            ).undoDeduplication()

        // Warm-up the cache to speed-up processing.
        requestAllPackageDetails(projectModuleInfo)

        val scopeNames = Scope.entries
            .filterNot { excludes.isScopeExcluded(it.descriptor) }
            .mapTo(mutableSetOf()) { scope ->
                val scopeName = scope.descriptor

                graphBuilder.addDependencies(project.id, scopeName, projectModuleInfo.getScopeDependencies(scope))

                scopeName
            }

        return ProjectAnalyzerResult(
            project = project.copy(scopeNames = scopeNames),
            packages = emptySet(),
            issues = issues
        ).let { listOf(it) }
    }

    private fun listModules(
        workingDir: File,
        issues: MutableList<Issue>,
        project: Project,
        isWorkspacePackage: Boolean,
        dependencyToType: Map<String, NpmDependencyType>,
        analysisRoot: File,
        excludes: Excludes
    ): ModuleInfo {
        // IMPORTANT:
        // the npm list command will build a complete dependency graph tree,
        // even the workspace package is not the dependencies of parent project, the npm list result also treat the workspace package as dependencies.
        // therefore the json output need to be further filtered.

        var packageNameWithNamespace =
            if (StringUtils.isNotEmpty(project.id.namespace)) project.id.namespace + "/" + project.id.name else project.id.name

        val listProcess = NpmCommand.run(workingDir, "list", "--depth", "Infinity", "--json", "--long")
        issues += listProcess.extractNpmIssues()

        var module = if (isWorkspacePackage) parseWorkspacePackageNpmList(
            listProcess.stdout,
            packageNameWithNamespace
        ) else parseNpmList(listProcess.stdout)

        val filterDependencies = module.dependencies.filterNot { dependency ->
            // filter the dependencies
            // 1. filter path excluded dependencies
            // 2. filter the workspace packages which are not the dependencies of parent project

            val file = File(dependency.value.path)
            var path = file.toPath()
            if (file.isSymbolicLink()) {
                // for workspace symbol link folder in node_modules, get the actual folder path
                if (dependency.value.path != null) {
                    val file = File(dependency.value.path).realFile()
                    path = file.toPath()
                    val cacheWorkspacePackage =
                        handler.workspacePackagesCache.firstOrNull { it -> it.workspaceName.equals(dependency.key) }
                    if (cacheWorkspacePackage == null) {
                        val wpk = WorkspacePackage(dependency.key, file, workingDir)
                        logger.info("The workspace package is added into workspace package cache, workspace package : $wpk")
                        handler.workspacePackagesCache.add(wpk)
                    }
                }
            }

            excludes.isPathExcluded(analysisRoot.toPath().relativize(path).invariantSeparatorsPathString)
                || !dependencyToType.containsKey(dependency.key)
        }

        // Return a new ModuleInfo with filtered dependencies
        return module.copy(dependencies = filterDependencies)
    }

    internal fun getRemotePackageDetails(packageName: String): PackageJson? {
        npmViewCache[packageName]?.let { return it }

        return runCatching {
            val process = NpmCommand.run("info", "--json", packageName).requireSuccess()

            parsePackageJson(process.stdout)
        }.onFailure { e ->
            logger.warn { "Error getting details for $packageName: ${e.message.orEmpty()}" }
        }.onSuccess {
            npmViewCache[packageName] = it
        }.getOrNull()
    }

    private fun installDependencies(analysisRoot: File, workingDir: File, allowDynamicVersions: Boolean): List<Issue> {
        requireLockfile(analysisRoot, workingDir, allowDynamicVersions) { managerType.hasLockfile(workingDir) }

        val options = listOfNotNull(
            "--ignore-scripts",
            "--no-audit",
            "--legacy-peer-deps".takeIf { config.legacyPeerDeps }
        )

        val subcommand = if (managerType.hasLockfile(workingDir)) "ci" else "install"

        val process = NpmCommand.run(workingDir, subcommand, *options.toTypedArray())

        return process.extractNpmIssues()
    }

    private fun requestAllPackageDetails(projectModuleInfo: ModuleInfo) {
        runBlocking {
            withContext(Dispatchers.IO.limitedParallelism(20)) {
                projectModuleInfo.getAllPackageNodeModuleIds().map { packageName ->
                    async { getRemotePackageDetails(packageName) }
                }.awaitAll()
            }
        }
    }
}

private enum class Scope(val descriptor: String) {
    DEPENDENCIES("dependencies"),
    DEV_DEPENDENCIES("devDependencies")
}

private fun ModuleInfo.getAllPackageNodeModuleIds(): Set<String> =
    buildSet {
        val queue = Scope.entries.flatMapTo(LinkedList()) { getScopeDependencies(it) }

        while (queue.isNotEmpty()) {
            val info = queue.removeFirst()

            @Suppress("ComplexCondition")
            if (!info.isProject && info.isInstalled && !info.name.isNullOrBlank() && !info.version.isNullOrBlank()) {
                add("${info.name}@${info.version}")
            }

            Scope.entries.flatMapTo(queue) { info.getScopeDependencies(it) }
        }
    }

private fun ModuleInfo.getScopeDependencies(scope: Scope) =
    when (scope) {
        Scope.DEPENDENCIES -> dependencies.values.filter { !it.dev }
        Scope.DEV_DEPENDENCIES -> dependencies.values.filter { it.dev && !it.optional }
    }

private fun ModuleInfo.undoDeduplication(): ModuleInfo {
    val replacements = getNonDeduplicatedModuleInfosForId()

    fun ModuleInfo.undoDeduplicationRec(ancestorsIds: Set<String> = emptySet()): ModuleInfo {
        val dependencyAncestorIds = ancestorsIds + setOfNotNull(id)
        val dependencies = (replacements[id] ?: this)
            .dependencies
            .filter { it.value.id !in dependencyAncestorIds } // break cycles.
            .mapValues { it.value.undoDeduplicationRec(dependencyAncestorIds) }

        return copy(dependencies = dependencies)
    }

    return undoDeduplicationRec()
}

private fun ModuleInfo.getNonDeduplicatedModuleInfosForId(): Map<String, ModuleInfo> {
    val queue = LinkedList<ModuleInfo>().apply { add(this@getNonDeduplicatedModuleInfosForId) }
    val result = mutableMapOf<String, ModuleInfo>()

    while (queue.isNotEmpty()) {
        val info = queue.removeFirst()

        if (info.id != null && info.dependencyConstraints.keys.subtract(info.dependencies.keys).isEmpty()) {
            result[info.id] = info
        }

        queue += info.dependencies.values
    }

    return result
}

internal fun List<String>.groupLines(vararg markers: String): List<String> {
    val ignorableLinePrefixes = setOf(
        "A complete log of this run can be found in: ",
        "code ",
        "errno ",
        "path ",
        "syscall "
    )
    val singleLinePrefixes =
        setOf("deprecated ", "invalid: ", "missing: ", "skipping integrity check for git dependency ")
    val minCommonPrefixLength = 5

    val issueLines = mapNotNull { line ->
        markers.firstNotNullOfOrNull { marker ->
            line.withoutPrefix(marker)?.takeUnless { ignorableLinePrefixes.any { prefix -> it.startsWith(prefix) } }
        }
    }

    var commonPrefix: String
    var previousPrefix = ""

    val collapsedLines = issueLines.distinct().fold(mutableListOf<String>()) { messages, line ->
        if (messages.isEmpty()) {
            // The first line is always added including the prefix. The prefix will be removed later.
            messages += line
        } else {
            // Find the longest common prefix that ends with space.
            commonPrefix = line.commonPrefixWith(messages.last())
            if (!commonPrefix.endsWith(' ')) {
                // Deal with prefixes being used on their own as separators.
                commonPrefix = if ("$commonPrefix " == previousPrefix || line.startsWith("$commonPrefix ")) {
                    "$commonPrefix "
                } else {
                    commonPrefix.dropLastWhile { it != ' ' }
                }
            }

            if (commonPrefix !in singleLinePrefixes && commonPrefix.length >= minCommonPrefixLength) {
                // Do not drop the whole prefix but keep the space when concatenating lines.
                messages[messages.size - 1] += line.drop(commonPrefix.length - 1).trimEnd()
                previousPrefix = commonPrefix
            } else {
                // Remove the prefix from previously added message start.
                messages[messages.size - 1] = messages.last().removePrefix(previousPrefix).trimStart()
                messages += line
            }
        }

        messages
    }

    if (collapsedLines.isNotEmpty()) {
        // Remove the prefix from the last added message start.
        collapsedLines[collapsedLines.size - 1] = collapsedLines.last().removePrefix(previousPrefix).trimStart()
    }

    val nonFooterLines = collapsedLines.takeWhile {
        // Skip any footer as a whole.
        it != "A complete log of this run can be found in:"
    }

    // If no lines but the last end with a dot, assume the message to be a single sentence.
    return if (
        nonFooterLines.size > 1 &&
        nonFooterLines.last().endsWith('.') &&
        nonFooterLines.subList(0, nonFooterLines.size - 1).none { it.endsWith('.') }
    ) {
        listOf(nonFooterLines.joinToString(" "))
    } else {
        nonFooterLines.map { it.trim() }
    }
}

internal fun ProcessCapture.extractNpmIssues(): List<Issue> {
    val lines = stderr.lines()
    val issues = mutableListOf<Issue>()

    // Generally forward issues from the NPM CLI to the ORT NPM package manager. Lower the severity of warnings to
    // hints, as warnings usually do not prevent the ORT NPM package manager from getting the dependencies right.
    lines.groupLines("npm WARN ", "npm warn ").mapTo(issues) {
        Issue(source = NpmFactory.descriptor.displayName, message = it, severity = Severity.HINT)
    }

    // For errors, however, something clearly went wrong, so keep the severity here.
    lines.groupLines("npm ERR! ", "npm error ").mapTo(issues) {
        Issue(source = NpmFactory.descriptor.displayName, message = it, severity = Severity.ERROR)
    }

    return issues
}

// Function to sort the list of package.json files, placing those with a non-empty "workspaces" field first
fun sortByWorkspaces(files: List<File>): List<File> {
    return files.sortedWith { file1, file2 ->
        val hasWorkspaces1 = hasNonEmptyWorkspacesConfig(file1)
        val hasWorkspaces2 = hasNonEmptyWorkspacesConfig(file2)

        when {
            hasWorkspaces1 && !hasWorkspaces2 -> -1  // file1 should come first
            !hasWorkspaces1 && hasWorkspaces2 -> 1   // file2 should come first
            else -> 0  // Maintain relative order if both or neither have "workspaces"
        }
    }
}


// Function to check if a given package.json file has a non-empty "workspaces" configuration
fun hasNonEmptyWorkspacesConfig(file: File): Boolean {
    return try {
        val jsonText = file.readText()
        val jsonElement = Json.parseToJsonElement(jsonText)
        val jsonObject = jsonElement.jsonObject
        val workspaces = jsonObject["workspaces"]

        // Check if "workspaces" exists and is not empty
        workspaces != null && when (workspaces) {
            is JsonArray -> workspaces.isNotEmpty()
            is JsonObject -> workspaces.keys.isNotEmpty()
            else -> false
        }
    } catch (e: Exception) {
        false  // If there's an error parsing the JSON, return false
    }
}

private enum class NpmDependencyType(val type: String) {
    DEPENDENCIES("dependencies"),
    DEV_DEPENDENCIES("devDependencies")
}

private fun listDependenciesByType(definitionFile: File): Map<String, NpmDependencyType> {
    val packageJson = parsePackageJson(definitionFile)
    val result = mutableMapOf<String, NpmDependencyType>()

    NpmDependencyType.entries.forEach { dependencyType ->
        packageJson.getScopeDependencies(dependencyType).keys.forEach {
            result += it to dependencyType
        }
    }

    return result
}

private fun PackageJson.getScopeDependencies(type: NpmDependencyType) =
    when (type) {
        NpmDependencyType.DEPENDENCIES -> dependencies
        NpmDependencyType.DEV_DEPENDENCIES -> devDependencies
    }
