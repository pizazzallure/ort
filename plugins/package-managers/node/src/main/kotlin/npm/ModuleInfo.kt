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

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.ossreviewtoolkit.utils.common.Os
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes

private val JSON = Json { ignoreUnknownKeys = true }

internal fun parseNpmList(json: String): ModuleInfo = JSON.decodeFromString(json)

/**
 * Only for NPM package manager to get the dependencies from workspace package.
 */
internal fun parseWorkspacePackageNpmList(json: String, packageName: String): ModuleInfo {
    val moduleInfo: ModuleInfo = JSON.decodeFromString(json)
    val workspacePackageModuleInfo = moduleInfo.dependencies.get(packageName)!!
    return workspacePackageModuleInfo
}

fun File.isSymbolicLink(): Boolean =
    runCatching {
        // Note that we cannot use exists() to check beforehand whether a symbolic link exists to avoid a
        // NoSuchFileException to be thrown as it returns "false" e.g. for dangling Windows junctions.
        Files.readAttributes(toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).let {
            it.isSymbolicLink || (Os.isWindows && it.isOther)
        }
    }.getOrDefault(false)


/**
 * Module information for installed NPM packages.
 */
@Serializable
internal data class ModuleInfo(
    /** The name of the package. */
    val name: String? = null,

    /** The resolved version of the package. */
    val version: String? = null,

    /** The path to the directory where the package is installed. */
    val path: String? = null,

    /** The ID of the NPM package. */
    @SerialName("_id")
    val id: String? = null,

    /** The dependencies of the package with unresolved versions. */
    @SerialName("_dependencies")
    val dependencyConstraints: Map<String, String> = emptyMap(),

    /** The dependencies of the package. */
    val dependencies: Map<String, ModuleInfo> = emptyMap(),

    /** A flag to indicate whether this is an optional dependency. */
    val optional: Boolean = false,

    /** A flag to indicate whether this is a development dependency. */
    val dev: Boolean = false,

    /** The URI from where the package was resolved. Starts with "file:" for local packages. */
    val resolved: String? = null
)

