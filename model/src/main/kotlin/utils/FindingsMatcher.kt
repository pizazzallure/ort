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

package org.ossreviewtoolkit.model.utils

import org.ossreviewtoolkit.model.AuthorFinding
import org.ossreviewtoolkit.model.CopyrightFinding
import org.ossreviewtoolkit.model.LicenseFinding
import org.ossreviewtoolkit.model.TextLocation
import org.ossreviewtoolkit.utils.spdx.*
import java.util.*
import kotlin.math.max
import kotlin.math.min

/**
 * A class for matching copyright and authors findings to license findings. Copyright statements and authors may be matched either to license
 * findings located nearby in the same file or to a license found in a license file whereas the given
 * [rootLicenseMatcher] determines whether a file is a license file.
 */
class FindingsMatcher(
    private val rootLicenseMatcher: RootLicenseMatcher = RootLicenseMatcher(),
    private val toleranceLines: Int = DEFAULT_TOLERANCE_LINES,
    private val expandToleranceLines: Int = DEFAULT_EXPAND_TOLERANCE_LINES
) {
    companion object {
        /**
         * The default value seems to be a good balance between associating findings separated by blank lines but not
         * skipping complete license statements.
         */
        const val DEFAULT_TOLERANCE_LINES = 5

        /**
         * The default value seems to be a good balance between associating findings separated by blank lines but not
         * skipping complete license statements.
         */
        const val DEFAULT_EXPAND_TOLERANCE_LINES = 2
    }

    /**
     * Return the line range in which copyright statements should be matched against the license finding at the
     * location given by [licenseStartLine] and [licenseEndLine]. The given [copyrightLines] must contain exactly all
     * lines of all copyright statements present in the file where the given license location points to.
     */
    private fun getMatchingRange(
        licenseStartLine: Int,
        licenseEndLine: Int,
        copyrightLines: Collection<Int>
    ): IntRange {
        val startLine = max(0, licenseStartLine - toleranceLines)
        val endLine = max(licenseStartLine + toleranceLines, licenseEndLine)
        val range = startLine..endLine

        var expandedStartLine = copyrightLines.filter { it in range }.minOrNull() ?: return range
        val queue = PriorityQueue<Int>(copyrightLines.size, compareByDescending { it })
        queue += copyrightLines.filter { it < expandedStartLine }

        while (queue.isNotEmpty()) {
            val line = queue.poll()
            if (expandedStartLine - line > expandToleranceLines) break

            expandedStartLine = line
        }

        return min(startLine, expandedStartLine)..endLine
    }

    /**
     * Return those statements in [copyrights] and authors in [authors] which match the license location given by [licenseStartLine] and
     * [licenseEndLine]. That matching is configured by [toleranceLines] and [expandToleranceLines].
     */
    private fun getClosestLicenseFinding(
        licenseFinding: LicenseFinding,
        copyrights: List<CopyrightFinding>,
        authors: List<AuthorFinding>
    ): MatchedLicenseFinding {
        require(
            copyrights.mapTo(mutableSetOf()) { it.location.path }.size <= 1
                && authors.mapTo(mutableSetOf()) { it.location.path }.size <= 1
        ) {
            "Given copyright statements and authors must all point to the same file."
        }

        val licenseStartLine = licenseFinding.location.startLine
        val licenseEndLine = licenseFinding.location.endLine

        val lineRange = getMatchingRange(licenseStartLine, licenseEndLine, copyrights.map { it.location.startLine })

        val filterCopyrights = copyrights.filterTo(mutableSetOf()) { it.location.startLine in lineRange }
        val filterAuthors = authors.filterTo(mutableSetOf()) { it.location.startLine in lineRange }

        return MatchedLicenseFinding(licenseFinding, filterCopyrights, filterAuthors)
    }

    /**
     * Associate copyright and author findings to license findings within a single file.
     */
    private fun matchFileFindings(
        licenses: List<LicenseFinding>,
        copyrights: List<CopyrightFinding>,
        authors: List<AuthorFinding>
    ): Map<LicenseFinding, MatchedLicenseFinding> {
        require((licenses.map { it.location.path } + copyrights.map { it.location.path } + authors.map { it.location.path }).distinct().size <= 1) {
            "The given license, copyright and author findings must all point to the same file."
        }

        // If there is only a single license finding, associate all copyright and authors findings with that license. If there is
        // no license return no matches.
        if (licenses.isEmpty()) {
            return emptyMap()
        }
        if (licenses.size == 1) {
            val matchedLicenseFinding: MatchedLicenseFinding =
                MatchedLicenseFinding(licenses[0], copyrights.toMutableSet(), authors.toMutableSet())
            return licenses.associateWith { matchedLicenseFinding }
        }

        // If there are multiple license findings in a single file, search for the closest copyright statements and authors
        // for each of these, if any.
        return licenses.associateWith { licenseFinding ->
            getClosestLicenseFinding(
                licenseFinding,
                copyrights,
                authors
            )
        }
    }

    /**
     * Associate the [copyrightFindings] and [authorFindings] to the [licenseFindings]. Copyright and author findings are matched to license findings
     * located nearby in the same file. Copyright and author findings that are not located close to a license finding are
     * associated to the root licenses instead. The root licenses are the licenses found in any of the license files
     * defined by [rootLicenseMatcher].
     */
    fun match(
        licenseFindings: Set<LicenseFinding>,
        copyrightFindings: Set<CopyrightFinding>,
        authorFindings: Set<AuthorFinding>
    ): FindingsMatcherResult {
        val licenseFindingsByPath = licenseFindings.groupBy { it.location.path }
        val copyrightFindingsByPath = copyrightFindings.groupBy { it.location.path }
        val authorFindingsByPath = authorFindings.groupBy { it.location.path }

        val paths = (licenseFindingsByPath.keys + copyrightFindingsByPath.keys + authorFindingsByPath.keys).toSet()

        val matchedFindings = mutableMapOf<LicenseFinding, MatchedLicenseFinding>()
        val unmatchedCopyrights = mutableSetOf<CopyrightFinding>()
        val unmatchedAuthors = mutableSetOf<AuthorFinding>()

        paths.forEach { path ->
            val licenses = licenseFindingsByPath[path].orEmpty()
            val copyrights = copyrightFindingsByPath[path].orEmpty()
            val authors = authorFindingsByPath[path].orEmpty()

            val matchedFileFindings = matchFileFindings(licenses, copyrights, authors)

            matchedFindings.merge(matchedFileFindings)

            val matchedCopyrights: MutableSet<CopyrightFinding> = mutableSetOf()
            val matchedAuthors: MutableSet<AuthorFinding> = mutableSetOf()
            matchedFileFindings.values.forEach { matchedLicenseFinding ->
                matchedCopyrights.addAll(matchedLicenseFinding.copyrightsFindings)
                matchedAuthors.addAll(matchedLicenseFinding.authorFindings)
            }

            unmatchedCopyrights += copyrights.toSet() - matchedCopyrights
            unmatchedAuthors += authors.toSet() - matchedAuthors
        }

        // check if unmatched copyright and authors is matched with root license
        val matchedRootLicenseFindings = matchWithRootLicenses(licenseFindings, unmatchedCopyrights, unmatchedAuthors)

        matchedFindings.merge(matchedRootLicenseFindings)

        // the copyright and author which match the root licenses will be removed from unmatched collection
        val matchedRootLicenseCopyrights: MutableSet<CopyrightFinding> = mutableSetOf()
        val matchedRootLicenseAuthors: MutableSet<AuthorFinding> = mutableSetOf()
        matchedRootLicenseFindings.values.forEach { matchedRootLicenseFinding ->
            matchedRootLicenseCopyrights.addAll(matchedRootLicenseFinding.copyrightsFindings)
            matchedRootLicenseAuthors.addAll(matchedRootLicenseFinding.authorFindings)
        }
        unmatchedCopyrights -= matchedRootLicenseCopyrights
        unmatchedAuthors -= matchedRootLicenseAuthors

        return FindingsMatcherResult(matchedFindings, unmatchedCopyrights, unmatchedAuthors)
    }

    /**
     * Associate the given [copyrightFindings] and [authorFindings] to its corresponding applicable root licenses. If no root license is
     * applicable to a given copyright finding and author finding, that copyright finding and author is not contained in the result.
     */
    private fun matchWithRootLicenses(
        licenseFindings: Set<LicenseFinding>,
        copyrightFindings: Set<CopyrightFinding>,
        authorFindings: MutableSet<AuthorFinding>
    ): Map<LicenseFinding, MatchedLicenseFinding> {
        val rootLicensesForDirectories = rootLicenseMatcher.getApplicableRootLicenseFindingsForDirectories(
            licenseFindings = licenseFindings,
            directories = copyrightFindings.map { it.location.directory() }
        )

        val result = mutableMapOf<LicenseFinding, MatchedLicenseFinding>()

        copyrightFindings.forEach { copyrightFinding ->
            rootLicensesForDirectories[copyrightFinding.location.directory()]?.forEach { rootLicenseFinding ->
                result.getOrPut(rootLicenseFinding) {
                    MatchedLicenseFinding(
                        rootLicenseFinding,
                        mutableSetOf(),
                        mutableSetOf()
                    )
                }.copyrightsFindings.add(copyrightFinding)
            }
        }

        authorFindings.forEach { authorFinding ->
            rootLicensesForDirectories[authorFinding.location.directory()]?.forEach { rootLicenseFinding ->
                result.getOrPut(rootLicenseFinding) {
                    MatchedLicenseFinding(
                        rootLicenseFinding,
                        mutableSetOf(),
                        mutableSetOf()
                    )
                }.authorFindings.add(authorFinding)
            }
        }

        return result
    }
}

/**
 * The result of the [FindingsMatcher].
 */
data class FindingsMatcherResult(
    /**
     * A map of [LicenseFinding]s mapped to their matched [CopyrightFinding]s and [AuthorFinding]s.
     */
    val matchedFindings: Map<LicenseFinding, MatchedLicenseFinding>,

    /**
     * All [CopyrightFinding]s that could not be matched to a [LicenseFinding].
     */
    val unmatchedCopyrights: Set<CopyrightFinding>,

    /**
     * All [AuthorFinding]s that could not be matched to a [LicenseFinding].
     */
    val unmatchedAuthors: MutableSet<AuthorFinding>
)

/**
 * The match license finding include:
 * 1. license finding
 * 2. matched copyrights statement for the license finding
 * 3. matched authors for the license finding
 */
data class MatchedLicenseFinding(

    val licenseFinding: LicenseFinding,

    // matched copyrights statement for the license finding
    val copyrightsFindings: MutableSet<CopyrightFinding>,

    // matched authors for the license finding
    val authorFindings: MutableSet<AuthorFinding>

)

private fun TextLocation.directory(): String = path.substringBeforeLast(delimiter = "/", missingDelimiterValue = "")

private fun MutableMap<LicenseFinding, MatchedLicenseFinding>.merge(
    other: Map<LicenseFinding, MatchedLicenseFinding>
) {
    other.forEach { (licenseFinding, matchedLicenseFinding) ->
        if (containsKey(licenseFinding)) {
            get(licenseFinding)?.copyrightsFindings?.addAll(matchedLicenseFinding.copyrightsFindings)
            get(licenseFinding)?.authorFindings?.addAll(matchedLicenseFinding.authorFindings)
        } else {
            put(licenseFinding, matchedLicenseFinding)
        }
    }
}

/**
 * Process [findings] for stand-alone license exceptions and associate them with nearby (according to [toleranceLines])
 * applicable licenses. Orphan license exceptions will get associated by [SpdxConstants.NOASSERTION]. Return the list of
 * resulting findings.
 */
fun associateLicensesWithExceptions(
    findings: Collection<LicenseFinding>,
    toleranceLines: Int = FindingsMatcher.DEFAULT_TOLERANCE_LINES
): Set<LicenseFinding> {
    val (licenses, exceptions) = findings.partition { SpdxLicenseException.forId(it.license.toString()) == null }

    val fixedLicenses = licenses.toMutableSet()

    val existingExceptions = licenses.mapNotNull { finding ->
        (finding.license as? SpdxLicenseWithExceptionExpression)?.exception?.let { it to finding.location }
    }

    val remainingExceptions = exceptions.filterNotTo(mutableSetOf()) {
        existingExceptions.any { (exception, location) ->
            it.license.toString() == exception && it.location in location
        }
    }

    val i = remainingExceptions.iterator()

    while (i.hasNext()) {
        val exception = i.next()

        // Determine all licenses the exception is applicable to.
        val applicableLicenses = SpdxLicenseException.mapping[exception.license.toString()].orEmpty().map { it.id }

        // Determine applicable license findings from the same path.
        val applicableLicenseFindings = licenses.filter {
            it.location.path == exception.location.path && it.license.toString() in applicableLicenses
        }

        // Find the closest license within the tolerance.
        val associatedLicenseFinding = applicableLicenseFindings
            .map { it to it.location.distanceTo(exception.location) }
            .sortedBy { it.second }
            .firstOrNull { it.second <= toleranceLines }
            ?.first

        if (associatedLicenseFinding != null) {
            // Add the fixed-up license with the exception.
            fixedLicenses += associatedLicenseFinding.copy(
                license = "${associatedLicenseFinding.license} ${SpdxExpression.WITH} ${exception.license}".toSpdx(),
                location = associatedLicenseFinding.location.copy(
                    startLine = min(associatedLicenseFinding.location.startLine, exception.location.startLine),
                    endLine = max(associatedLicenseFinding.location.endLine, exception.location.endLine)
                )
            )

            // Remove the original license and the stand-alone exception.
            fixedLicenses.remove(associatedLicenseFinding)
            i.remove()
        }
    }

    // Associate remaining "orphan" exceptions with "NOASSERTION" to turn them into valid SPDX expressions and at the
    // same time "marking" them for review as "NOASSERTION" is not a real license.
    remainingExceptions.mapTo(fixedLicenses) { exception ->
        exception.copy(license = "${SpdxConstants.NOASSERTION} ${SpdxExpression.WITH} ${exception.license}".toSpdx())
    }

    return fixedLicenses.mapTo(mutableSetOf()) { it.copy(license = associateLicensesWithExceptions(it.license)) }
}

/**
 * Process [license] for stand-alone license exceptions as part of compound expressions and associate them with
 * applicable licenses. Orphan license exceptions will get associated by [SpdxConstants.NOASSERTION]. Return a new
 * expression that does not contain stand-alone license exceptions anymore.
 */
internal fun associateLicensesWithExceptions(license: SpdxExpression): SpdxExpression {
    // If this is not a compound expression, there can be no stand-alone license exceptions with belonging licenses.
    if (license !is SpdxCompoundExpression) return license

    // Exclusively operate on AND-only expressions without further nested expressions.
    val hasOnlyAndOperator = license.operator == SpdxOperator.AND && "(" !in license.toString()
    if (!hasOnlyAndOperator) {
        return SpdxCompoundExpression(
            associateLicensesWithExceptions(license.left),
            license.operator,
            associateLicensesWithExceptions(license.right)
        )
    }

    val handledLicenses = mutableSetOf<SpdxSingleLicenseExpression>()
    val simpleLicenses = mutableSetOf<SpdxSimpleExpression>()
    val associatedLicenses = mutableSetOf<SpdxSimpleExpression>()
    val remainingExceptions = mutableSetOf<SpdxSingleLicenseExpression>()

    // Divide the AND-operands into exceptions, simple expressions, and licenses than cannot be used with an exception.
    license.decompose().forEach {
        when {
            SpdxLicenseException.forId(it.toString()) != null -> remainingExceptions += it
            it is SpdxSimpleExpression -> simpleLicenses += it
            else -> handledLicenses += it
        }
    }

    val i = remainingExceptions.iterator()

    while (i.hasNext()) {
        val exception = i.next()
        val exceptionString = exception.toString()

        // Determine all licenses the exception is applicable to.
        val applicableLicenses = SpdxLicenseException.mapping[exceptionString].orEmpty().mapTo(mutableSetOf()) {
            SpdxLicenseIdExpression(it.id)
        }

        // Associate all remaining licenses that are applicable with the exception and remove the exception.
        val licenses = simpleLicenses.intersect(applicableLicenses)
        if (licenses.isEmpty()) continue

        licenses.forEach {
            handledLicenses += SpdxLicenseWithExceptionExpression(it, exceptionString)
        }

        associatedLicenses += licenses
        i.remove()
    }

    handledLicenses += simpleLicenses - associatedLicenses

    // Associate remaining "orphan" exceptions with "NOASSERTION" to turn them into valid SPDX expressions.
    handledLicenses += remainingExceptions.map {
        SpdxLicenseWithExceptionExpression(SpdxLicenseIdExpression(SpdxConstants.NOASSERTION), it.toString())
    }

    // Recreate the compound AND-expression from the associated licenses.
    return handledLicenses.reduce(SpdxExpression::and)
}
