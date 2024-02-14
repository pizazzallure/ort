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

package org.ossreviewtoolkit.reporter

import org.ossreviewtoolkit.utils.spdx.*
import java.io.File

class DefaultLicenseTextProvider(private val licenseTextDirectories: List<File> = emptyList()) : LicenseTextProvider,
    CustomLicenseTextProvider {
    override fun getLicenseText(licenseId: String): String? =
        getLicenseText(
            id = licenseId,
            handleExceptions = true,
            licenseTextDirectories = licenseTextDirectories
        )

    override fun getLicenseTextReader(licenseId: String): (() -> String)? =
        getLicenseTextReader(
            id = licenseId,
            handleExceptions = true,
            licenseTextDirectories = licenseTextDirectories
        )

    override fun hasLicenseText(licenseId: String): Boolean =
        hasLicenseText(
            id = licenseId,
            handleExceptions = true,
            licenseTextDirectories = licenseTextDirectories
        )

    override fun getCustomLicenseText(licenseId: String): String? =
        getCustomLicenseText(
            id = licenseId,
            licenseTextDirectories = licenseTextDirectories
        )

    override fun getCustomLicenseTextReader(licenseId: String): (() -> String)? =
        getCustomLicenseTextReader(
            id = licenseId,
            licenseTextDirectories = licenseTextDirectories
        )

    override fun hasCustomLicenseText(licenseId: String): Boolean =
        hasCustomLicenseText(
            id = licenseId,
            licenseTextDirectories = licenseTextDirectories
        )
}
