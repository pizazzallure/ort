/*
 * Copyright (C) 2022 Porsche AG
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

package org.ossreviewtoolkit.plugins.reporters.interfaceaudit

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import org.ossreviewtoolkit.model.*
import org.ossreviewtoolkit.model.config.PathExclude
import org.ossreviewtoolkit.model.config.PathExcludeReason
import org.ossreviewtoolkit.model.config.PluginConfiguration
import org.ossreviewtoolkit.model.licenses.*
import org.ossreviewtoolkit.model.vulnerabilities.*
import org.ossreviewtoolkit.plugins.reporters.evaluatedmodel.EvaluatedFindingType
import org.ossreviewtoolkit.plugins.reporters.evaluatedmodel.EvaluatedModel
import org.ossreviewtoolkit.reporter.Reporter
import org.ossreviewtoolkit.reporter.ReporterInput
import java.io.File
import java.net.URI
import java.text.SimpleDateFormat
import java.time.Instant
import java.util.*
import java.util.stream.Collectors

class InterfaceAuditReportReporter : Reporter {
    override val type = "InterfaceAuditReport"

    companion object {

        const val OPTION_DEDUPLICATE_DEPENDENCY_TREE = "deduplicateDependencyTree"

        fun <T> mergeSortedSets(vararg sets: Set<T>): SortedSet<T> {
            val result = TreeSet<T>()

            for (set in sets) {
                result += set
            }

            return result
        }

        fun <T> mergeAnySets(vararg sets: Set<T>): Set<T> {
            val result = HashSet<T>()

            for (set in sets) {
                result += set
            }

            return result
        }

        fun CuratedPackage.curatedAuthors(): SortedSet<String> {
            val result: SortedSet<String> = TreeSet()

            curations.forEach { packageCuration ->
                packageCuration.curation.authors?.let { result.addAll(it) }
            }

            return result
        }

        fun CuratedPackage.curatedCopyrightHolders(): SortedSet<String> {
            val result: SortedSet<String> = TreeSet()

            curations.forEach { packageCuration ->
                packageCuration.curation.copyrightHolders?.let { result.addAll(it) }
            }

            return result
        }

        fun Package.sortedAuthors(): SortedSet<String> {
            val result: SortedSet<String> = TreeSet()

            result.addAll(authors)

            return result
        }
    }

    override fun generateReport(input: ReporterInput, outputDir: File, config: PluginConfiguration): List<File> {
        val outputFiles = LinkedList<File>()

        outputFiles += InterfaceAuditReporter().generateReport(input, outputDir, config)

        return outputFiles
    }

    class InterfaceAuditReporter {
        private var reportFileName = "Interface-Audit-Report.json"

        fun generateReport(input: ReporterInput, outputDir: File, config: PluginConfiguration): File {

            val evaluatedModel = EvaluatedModel.create(
                input,
                config.options[OPTION_DEDUPLICATE_DEPENDENCY_TREE].toBoolean()
            )

            evaluatedModel.packages

            val mapper = JsonMapper().registerModule(JavaTimeModule()).setDateFormat(SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX"))
            mapper.propertyNamingStrategy = PropertyNamingStrategies.LOWER_CAMEL_CASE

            val licenseModelJson = mapper
                .writer()
                .writeValueAsString(buildDependency(input))

            val outputFile = outputDir.resolve(reportFileName)

            outputFile.bufferedWriter().use { it.write(licenseModelJson) }


            return outputFile
        }

        private fun buildDependency(input: ReporterInput): Dependency {
            val combinedSBom: MutableMap<Identifier, SoftwareBillOfMaterial> = HashMap()
            var vulnerabilityBillOfMaterial: VulnerabilityResult? = null

            for (project in input.ortResult.getProjects()) {
                val scopeMap: MutableMap<Identifier, MutableSet<String>> = HashMap()

                input.ortResult.dependencyNavigator.scopeDependencies(project)
                    .forEach { (scopeName, identifiers) ->
                        identifiers.forEach { packageId ->
                            scopeMap.computeIfAbsent(packageId) { HashSet() }.add(scopeName)
                        }
                    }

                buildSBom(input, project, scopeMap).forEach { identifier, sbom ->
                    combinedSBom.merge(identifier, sbom) { left, right -> mergeSbom(left, right) }
                }
            }

            input.ortResult.advisor?.let { advisorRun ->
                vulnerabilityBillOfMaterial = VulnerabilityResult(
                    startStamp = advisorRun.startTime,
                    endStamp = advisorRun.endTime,
                    vulnerabilities = buildVulnerabilities(advisorRun.results)
                )
            }

            return Dependency(
                softwareBillOfMaterial = combinedSBom.values.toList(),
                vulnerabilityBillOfMaterial = vulnerabilityBillOfMaterial
            )
        }

        private fun buildVulnerabilities(advisorRecord: AdvisorRecord): List<VulnerabilityRecord> {
            val vulnerabilityRecords: MutableList<VulnerabilityRecord> = LinkedList()

            advisorRecord.advisorResults.forEach { packageId, advisorResults ->
                advisorResults.forEach { advisorResult ->
                    vulnerabilityRecords.add(
                        VulnerabilityRecord(
                            dependencyCoordinate = packageId.toCoordinates(),
                            advisor = advisorResult.advisor.name,
                            startStamp = advisorResult.summary.startTime,
                            endStamp = advisorResult.summary.endTime,
                            vulnerabilities = buildVulnerabilityDetails(advisorResult.vulnerabilities)
                        )
                    )
                }
            }
            return vulnerabilityRecords
        }

        private fun buildVulnerabilityDetails(vulnerabilities: List<Vulnerability>): List<VulnerabilityDetailRecord> {
            val vulnerabilityDetailRecords: MutableList<VulnerabilityDetailRecord> = LinkedList()

            vulnerabilities.forEach { vulnerability ->
                vulnerabilityDetailRecords.add(
                    VulnerabilityDetailRecord(
                        vulnerabilityId = vulnerability.id,
                        description = vulnerability.description,
                        summary = vulnerability.summary,
                        references = buildVulnerabilityReferences(vulnerability.references)
                    )
                )
            }

            return vulnerabilityDetailRecords
        }

        private fun buildVulnerabilityReferences(references : List<VulnerabilityReference>) : List<VulnerabilityReferenceRecord> {
            val vulnerabilityReferenceRecords: MutableList<VulnerabilityReferenceRecord> = LinkedList()

            references.forEach { reference ->
                vulnerabilityReferenceRecords.add(
                    VulnerabilityReferenceRecord(
                    referenceUri = reference.url,
                    scoringSystem = reference.scoringSystem,
                    severity = reference.severity
                )
                )
            }

            return vulnerabilityReferenceRecords
        }

        private fun mergeSbom(
            left: SoftwareBillOfMaterial,
            right: SoftwareBillOfMaterial
        ): SoftwareBillOfMaterial {
            val scopes = left.scopes.toMutableSet();

            scopes.addAll(right.scopes)

            return SoftwareBillOfMaterial(
                dependencyCoordinate = left.dependencyCoordinate,
                dependencyNamespace = left.dependencyNamespace,
                dependencyName = left.dependencyName,
                version = left.version,
                scopes = scopes,
                processedRepositoryUri = left.processedRepositoryUri,
                remoteSourceArtifactUri = left.remoteSourceArtifactUri,
                remoteBinaryArtifactUri = left.remoteBinaryArtifactUri,
                homepageUri = left.homepageUri,
                licenseDetail = left.licenseDetail,
                copyrightDetail = left.copyrightDetail,
                authorDetail = left.authorDetail,
                transitiveDependency = left.transitiveDependency,
                ruleViolation = left.ruleViolation
            )
        }

        private fun buildSBom(
            input: ReporterInput,
            project: Project,
            scopeMap: Map<Identifier, Set<String>>
        ): Map<Identifier, SoftwareBillOfMaterial> =
            input.ortResult.collectDependencies(project.id)
                .filter { !input.ortResult.isExcluded(it) }
                .filter { input.ortResult.getPackage(it) != null }
                .associateWith { id ->
                    val ortResult = input.ortResult
                    // We know that a package exists for the reference.
                    val curatedPkg = ortResult.getPackage(id)!!
                    val pkg = curatedPkg.metadata

                    SoftwareBillOfMaterial(
                        dependencyCoordinate = id.toCoordinates(),
                        dependencyNamespace = id.namespace,
                        dependencyName = id.name,
                        version = id.version,
                        scopes = scopeMap.getOrDefault(id, HashSet()),
                        processedRepositoryUri = pkg.vcsProcessed.url,
                        remoteSourceArtifactUri = pkg.sourceArtifact.url,
                        remoteBinaryArtifactUri = pkg.binaryArtifact.url,
                        homepageUri = curatedPkg.metadata.homepageUrl,
                        licenseDetail = buildLicenseDetail(input, curatedPkg),
                        copyrightDetail = buildCopyrightDetail(input, curatedPkg),
                        authorDetail = buildAuthorDetail(curatedPkg),
                        transitiveDependency = buildPackageDependencies(ortResult, curatedPkg),
                        ruleViolation = buildRuleViolations(ortResult)
                    )
                }

        private fun buildPackageDependencies(
            ortResult: OrtResult,
            curatedPkg: CuratedPackage
        ): List<TransitiveDependency> {
            val directDependencies = ortResult
                .collectDependencies(curatedPkg.metadata.id, 1)
                .map { it.toCoordinates() }

            return ortResult
                .collectDependencies(curatedPkg.metadata.id)
                .map {
                    val coordinates = it.toCoordinates()

                    TransitiveDependency(
                        dependencyCoordinate = coordinates,
                        isDirect = directDependencies.contains(coordinates)
                    )
                }
        }

        private fun buildRuleViolations(ortResult: OrtResult): List<RuleViolation> =
            ortResult.getRuleViolations(true).stream()
                .map {
                    RuleViolation(
                        ruleName = it.rule,
                        spdxLicenseName = when (it.license) {
                            null -> null
                            else -> it.license!!.simpleLicense()
                        },
                        licenseSource = when (it.license) {
                            null -> null
                            else -> it.license!!.getLicenseUrl()
                        },
                        severity = it.severity.name,
                        message = it.message,
//                        howToFix = it.howToFix
                    )
                }
                .collect(Collectors.toList())

        private fun buildAuthorDetail(curatedPkg: CuratedPackage): AuthorDetail =
            AuthorDetail(
                author = mergeSortedSets(curatedPkg.metadata.sortedAuthors(),
                    curatedPkg.curatedAuthors())
            )

        private fun buildLicenseDetail(input: ReporterInput, curatedPkg: CuratedPackage): List<LicenseDetail> =
            input.licenseInfoResolver
                .resolveLicenseInfo(curatedPkg.metadata.id)
                .filterExcluded()
                .licenses.stream()
                .map {
                    val licenseId = it.license.simpleLicense()
                    LicenseDetail(
                        spdxLicenseName = licenseId,
                        licenseText = input.licenseTextProvider.getLicenseText(licenseId),
                        copyrights = it.getCopyrights(),
                        locations = it.locations.map { it.toDataplatform() }.toCollection(HashSet())
                    )
                }
                .collect(Collectors.toList())

        private fun buildLicenseCopyrightStatements(input: ReporterInput, curatedPkg: CuratedPackage): Set<String> {
            val copyrightStatements: MutableSet<String> = HashSet()

            input.licenseInfoResolver
                .resolveLicenseInfo(curatedPkg.metadata.id)
                .filterExcluded()
                .licenses.stream()
                .map { resolvedLicense ->
                    copyrightStatements.addAll(resolvedLicense.getCopyrights())

                    if (!resolvedLicense.isDetectedExcluded) {
                        resolvedLicense
                            .locations.map { it.toDataplatform() }
                            .forEach { licenseLocation ->
                                licenseLocation.copyrightFindings.forEach { licenseCopyrightFinding ->
                                    copyrightStatements.add(licenseCopyrightFinding.statement)
                                }
                            }
                    }
                }

            return copyrightStatements
        }

        private fun buildCopyrightDetail(input: ReporterInput, curatedPkg: CuratedPackage): CopyrightDetail =
            CopyrightDetail(
                copyrightHolder = buildCopyrightHolders(curatedPkg),
                copyrightStatement = buildCopyrightStatements(input, curatedPkg)
            )

        private fun buildCopyrightHolders(curatedPkg: CuratedPackage): Set<String> =
            mergeSortedSets(curatedPkg.metadata.copyrightHolders, curatedPkg.curatedCopyrightHolders())

        private fun buildCopyrightStatements(input: ReporterInput, curatedPkg: CuratedPackage): Set<String> =
            mergeAnySets(
                input.licenseInfoResolver
                    .resolveLicenseInfo(curatedPkg.metadata.id)
                    .filterExcluded()
                    .getCopyrights(),
                buildLicenseCopyrightStatements(input, curatedPkg)
            )

        private data class Dependency(
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val softwareBillOfMaterial: List<SoftwareBillOfMaterial>,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val vulnerabilityBillOfMaterial: VulnerabilityResult?
        )

        private data class VulnerabilityResult(
            val startStamp: Instant,
            val endStamp: Instant,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val vulnerabilities: List<VulnerabilityRecord>
        )

        private data class VulnerabilityRecord(
            val dependencyCoordinate: String,
            val advisor: String,
            val startStamp: Instant,
            val endStamp: Instant,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val vulnerabilities: List<VulnerabilityDetailRecord>
        )

        private data class VulnerabilityDetailRecord(
            val vulnerabilityId: String,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val description: String?,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val summary: String?,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val references: List<VulnerabilityReferenceRecord>,
        )

        private data class VulnerabilityReferenceRecord(
            val referenceUri: URI,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val scoringSystem: String?,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val severity: String?,
        )

        private data class SoftwareBillOfMaterial(
            val dependencyCoordinate: String,
            val dependencyNamespace: String,
            val dependencyName: String,
            val version: String,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val scopes: Set<String>,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val processedRepositoryUri: String,
            @JsonInclude(JsonInclude.Include.NON_EMPTY)
            val homepageUri: String,
            @JsonInclude(JsonInclude.Include.NON_EMPTY)
            val remoteSourceArtifactUri: String,
            @JsonInclude(JsonInclude.Include.NON_EMPTY)
            val remoteBinaryArtifactUri: String,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val licenseDetail: List<LicenseDetail>,
            val copyrightDetail: CopyrightDetail,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val authorDetail: AuthorDetail,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val transitiveDependency: List<TransitiveDependency>,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val ruleViolation: List<RuleViolation>
        )

        private data class LicenseDetail(
            val spdxLicenseName: String,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val licenseText: String?,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val copyrights: Set<String>,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val locations: Set<LicenseLocation>
        )

        data class LicenseLocation(
            val provenance: LicenseProvenance,
            val location: DataplatformTextLocation,
            val matchingPathExcludes: List<DataplatformPathExclude>,
            val copyrightFindings: Set<LicenseCopyrightFinding>
        )

        data class LicenseCopyrightFinding(
            val statement: String,
            val location: DataplatformTextLocation,
            val matchingPathExcludes: List<DataplatformPathExclude>,
            val findingType: ResolvedCopyrightSource
        )

        data class DataplatformTextLocation(
            val path: String,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val startLine: Int = 0,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val endLine: Int = 0
        )

        data class DataplatformPathExclude(
            val pathPattern: String,
            val reason: PathExcludeReason
        )

        enum class LicenseProvenance {
            UNKNOWN,
            KNOWN,
            ARTIFACT,
            REPOSITORY
        }

        private data class CopyrightDetail(
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val copyrightHolder: Set<String>,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT)
            val copyrightStatement: Set<String>
        )

        private data class AuthorDetail(
            val author: Set<String>
        )

        private data class TransitiveDependency(
            val dependencyCoordinate: String,
            val isDirect: Boolean,
        )

        private data class RuleViolation(
            val ruleName: String,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val spdxLicenseName: String?,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            val licenseSource: String?,
            val severity: String,
            val message: String,
//            val howToFix: String
        )

        fun PathExclude.toDataplatform(): DataplatformPathExclude = DataplatformPathExclude(
            this.pattern,
            this.reason
        )

        fun TextLocation.toDataplatform(): DataplatformTextLocation = DataplatformTextLocation(
            this.path,
            this.startLine,
            this.endLine
        )

        fun Provenance.toDataplatform(): LicenseProvenance {
            if (this is ArtifactProvenance) {
                return LicenseProvenance.ARTIFACT
            } else if (this is RepositoryProvenance) {
                return LicenseProvenance.REPOSITORY
            } else if (this is KnownProvenance) {
                return LicenseProvenance.KNOWN
            } else {
                return LicenseProvenance.UNKNOWN
            }
        }

        fun ResolvedLicenseLocation.toDataplatform(): LicenseLocation = LicenseLocation(
            provenance = this.provenance.toDataplatform(),
            location = this.location.toDataplatform(),
            matchingPathExcludes = matchingPathExcludes.map { it.toDataplatform() }.toCollection(ArrayList()),
            copyrightFindings = this.copyrights.map { it.toDataplatform() }.toCollection(HashSet())
        )

        fun ResolvedCopyrightFinding.toDataplatform(): LicenseCopyrightFinding = LicenseCopyrightFinding(
            statement = this.statement,
            location = this.location.toDataplatform(),
            matchingPathExcludes = matchingPathExcludes.map { it.toDataplatform() }.toCollection(ArrayList()),
            findingType = this.findingType
        )

    }

}

