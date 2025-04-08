/*
 * Copyright (C) 2024 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
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

import org.apache.logging.log4j.kotlin.logger
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageLinkage
import org.ossreviewtoolkit.model.config.Excludes
import org.ossreviewtoolkit.model.utils.DependencyHandler
import org.ossreviewtoolkit.plugins.packagemanagers.node.*
import org.ossreviewtoolkit.plugins.packagemanagers.node.yarn.WorkspacePackage
import org.ossreviewtoolkit.utils.common.isSymbolicLink
import org.ossreviewtoolkit.utils.common.realFile
import java.io.File
import kotlin.io.path.invariantSeparatorsPathString

internal class NpmDependencyHandler(
    private val projectType: String,
    private val getPackageDetails: GetPackageDetailsFun
) : DependencyHandler<ModuleInfo> {
    lateinit var analysisRoot: File
    lateinit var excludes: Excludes

    private val packageJsonCache = mutableMapOf<File, PackageJson>()

    /**
     * The detected definition files resolution is independent of each other.
     * before npm install on workspace package dir, we do not know if the current definition file is for workspace package,
     * therefore the parent project of workspace packages should be always resolved first,
     * then we can know the subordinated workspace packages and cache them in this map.
     *
     * Important: when execute npm install on workspace package dir, the node_modules dir is generated in the parent project dir, not the current workspace package dir.
     */
    val workspacePackagesCache: MutableList<WorkspacePackage> = mutableListOf()

    override fun identifierFor(dependency: ModuleInfo): Identifier {
        val type = if (dependency.isProject) projectType else "NPM"
        val (namespace, name) = splitNamespaceAndName(dependency.name.orEmpty())
        val version = if (dependency.isProject) {
            val packageJson = packageJsonCache.getOrPut(dependency.packageJsonFile.realFile()) {
                parsePackageJson(dependency.packageJsonFile)
            }

            packageJson.version.orEmpty()
        } else {
            dependency.version?.takeUnless { it.startsWith("link:") || it.startsWith("file:") }.orEmpty()
        }

        return Identifier(type, namespace, name, version)
    }

    override fun dependenciesFor(dependency: ModuleInfo): List<ModuleInfo> {
        val filteredDependencies = dependency.dependencies.mapNotNull { (key, module) ->
            val workspacePackage = workspacePackagesCache.find { it.workspaceName == key }

            val isExcluded = workspacePackage?.let {
                excludes.isPathExcluded(
                    analysisRoot.toPath()
                        .relativize(it.workspacePackageDir.toPath().normalize())
                        .invariantSeparatorsPathString
                )
            } ?: false

            if (isExcluded) {
                logger.warn { "Excluding dependency: $key (Workspace Package: ${workspacePackage?.workspaceName})" }
                null // Exclude this dependency
            } else {
                module // Keep this dependency
            }
        }

        return filteredDependencies.filter { it.isInstalled }
    }

    override fun linkageFor(dependency: ModuleInfo): PackageLinkage =
        PackageLinkage.DYNAMIC.takeUnless { dependency.isProject || dependency.workingDir.isSymbolicLink() }
            ?: PackageLinkage.PROJECT_DYNAMIC

    override fun createPackage(dependency: ModuleInfo, issues: MutableCollection<Issue>): Package? =
        dependency.takeUnless { it.isProject || !it.isInstalled || dependency.workingDir.isSymbolicLink() }?.let {
            parsePackage(it.packageJsonFile, getPackageDetails)
        }
}

private val ModuleInfo.workingDir: File get() = File(path)

internal val ModuleInfo.isInstalled: Boolean get() = path != null

internal val ModuleInfo.isProject: Boolean get() = resolved == null

private val ModuleInfo.packageJsonFile: File
    get() =
        File(
            checkNotNull(path) {
                "The path to '${NodePackageManagerType.DEFINITION_FILE}' is null in $this."
            },
            NodePackageManagerType.DEFINITION_FILE
        )
