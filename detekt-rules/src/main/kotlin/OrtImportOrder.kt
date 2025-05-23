/*
 * Copyright (C) 2020 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
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

package org.ossreviewtoolkit.detekt

import io.github.detekt.psi.absolutePath

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity

import org.jetbrains.kotlin.com.intellij.psi.PsiWhiteSpace
import org.jetbrains.kotlin.com.intellij.psi.impl.source.tree.PsiWhiteSpaceImpl
import org.jetbrains.kotlin.name.FqName
import org.jetbrains.kotlin.psi.KtImportDirective
import org.jetbrains.kotlin.psi.KtImportList
import org.jetbrains.kotlin.psi.KtPsiFactory
import org.jetbrains.kotlin.psi.psiUtil.allChildren
import org.jetbrains.kotlin.resolve.ImportPath

class OrtImportOrder(config: Config) : Rule(config) {
    private val commonTopLevelDomains = listOf("com", "org", "io")

    override val issue = Issue(
        javaClass.simpleName,
        Severity.Style,
        "Reports files that do not follow ORT's order for imports",
        Debt.FIVE_MINS
    )

    override fun visitImportList(importList: KtImportList) {
        super.visitImportList(importList)

        // Need to call importList.node.getChildren(null) instead of importList.getChildren(),
        // since the latter returns the imports without blank lines.
        val children = importList.node.getChildren(null)

        if (children.isEmpty()) return

        val importPaths = children.mapNotNull {
            when (val psi = it.psi) {
                is KtImportDirective -> psi.importPath.toString()
                // Between two imports there is a child PSI of type whitespace.
                // For 'n' blank lines in between, the text of this child contains
                // 'n + 1' line breaks. Thus, a single blank line is represented by "\n\n".
                is PsiWhiteSpace -> if (psi.text == "\n\n") "" else null
                else -> null
            }
        }

        val expectedImportOrder = createExpectedImportOrder(importPaths)

        if (importPaths != expectedImportOrder) {
            if (autoCorrect) fixImportListOrder(importList, expectedImportOrder)

            val path = importList.containingKtFile.absolutePath()
            val message = "Imports in file '$path' are not sorted alphabetically or single blank lines are missing " +
                "between different top-level packages"
            val finding = CodeSmell(
                issue,
                // Use the message as the name to also see it in CLI output and not only in the report files.
                Entity.from(importList).copy(name = message),
                message
            )
            report(finding)
        }
    }

    private fun fixImportListOrder(importList: KtImportList, expectedImportOrder: List<String>) {
        val project = importList.project
        val factory = KtPsiFactory(project)

        // Remove all existing imports and re-add them in the expected order.
        importList.allChildren.toList().forEach { it.delete() }
        expectedImportOrder.forEach { importPath ->
            if (importPath.isNotEmpty()) {
                val importDirective = factory.createImportDirective(ImportPath(FqName(importPath), false))
                importList.add(importDirective)
                importList.addNewLine()
            } else {
                importList.addNewLine()
            }
        }

        // Ensure the last empty line is preserved.
        if (expectedImportOrder.last().isNotEmpty()) importList.addNewLine()
    }

    private fun createExpectedImportOrder(importPaths: List<String>): List<String> {
        val expectedImportPaths = mutableListOf<String>()

        val (importPathsWithDot, importPathsWithoutDot) = importPaths.filter(String::isNotEmpty)
            .sorted()
            .partition { '.' in it }

        val sortedImportPathsWithDotAndBlankLines = createImportListWithBlankLines(importPathsWithDot)

        expectedImportPaths += importPathsWithoutDot
        if (expectedImportPaths.isNotEmpty()) expectedImportPaths += ""

        expectedImportPaths += sortedImportPathsWithDotAndBlankLines
        if (expectedImportPaths.isNotEmpty()) expectedImportPaths.removeLast()

        return expectedImportPaths
    }

    private fun createImportListWithBlankLines(importPaths: List<String>): List<String> {
        val pathsWithBlankLines = mutableListOf<String>()

        importPaths.groupBy { getTopLevelPackage(it) }.forEach {
            pathsWithBlankLines += it.value
            pathsWithBlankLines += ""
        }

        return pathsWithBlankLines
    }

    private fun getTopLevelPackage(importPath: String): String {
        val dotIndex = importPath.indexOf(".")
        var topLevelName = importPath.substring(0, dotIndex)

        if (topLevelName in commonTopLevelDomains) {
            val secondDotIndex = importPath.indexOf(".", dotIndex + 1)
            topLevelName = importPath.substring(0, secondDotIndex)
        }

        return topLevelName
    }
}

private fun KtImportList.addNewLine() = node.addChild(PsiWhiteSpaceImpl("\n"), null)
