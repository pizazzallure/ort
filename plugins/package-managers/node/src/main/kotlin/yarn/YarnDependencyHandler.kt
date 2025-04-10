/*
 * Copyright (C) 2021 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
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

package org.ossreviewtoolkit.plugins.packagemanagers.node.yarn

import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageLinkage
import org.ossreviewtoolkit.model.utils.DependencyHandler
import org.ossreviewtoolkit.plugins.packagemanagers.node.parsePackage

internal class YarnDependencyHandler(private val yarn: Yarn) : DependencyHandler<ModuleInfo> {
    override fun identifierFor(dependency: ModuleInfo): Identifier = dependency.id

    override fun dependenciesFor(dependency: ModuleInfo): List<ModuleInfo> = dependency.dependencies.toList()

    override fun linkageFor(dependency: ModuleInfo): PackageLinkage =
        PackageLinkage.DYNAMIC.takeUnless { dependency.isProject } ?: PackageLinkage.PROJECT_DYNAMIC

    override fun createPackage(dependency: ModuleInfo, issues: MutableCollection<Issue>): Package? =
        if (dependency.isProject) null else parsePackage(dependency.packageFile, yarn::getRemotePackageDetails)
}
