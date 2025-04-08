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

@file:Suppress("Filename")

package org.ossreviewtoolkit.plugins.packagemanagers.node

import org.apache.logging.log4j.kotlin.logger
import org.ossreviewtoolkit.utils.common.Os
import org.ossreviewtoolkit.utils.common.isSymbolicLink
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.nio.file.StandardCopyOption
import kotlin.io.path.createTempDirectory
import kotlin.io.path.moveTo

/**
 * A convenience function that stashes directories using a [NpmDirectoryStash] instance.
 *
 * The difference between [NpmDirectoryStash] and [DirectoryStash] is,
 * [NpmDirectoryStash] do not delete the symbol link folder recursively, it will not delete the actual files in symbol link folder.
 * The [DirectoryStash] will recursively delete the orginal workspace package folder in code repo after close stash.
 */
fun npmStashDirectories(vararg directories: File): Closeable = NpmDirectoryStash(setOf(*directories))

/**
 * A [Closeable] class which temporarily moves away directories and moves them back on close. Any conflicting directory
 * created at the location of an original directory is deleted before the original state is restored. If a specified
 * directory did not exist on initialization, it will also not exist on close.
 */
class NpmDirectoryStash(directories: Set<File>) : Closeable {
    private val stashedDirectories: Map<File, File?> = directories.associateWith { originalDir ->
        // Check this on each iteration instead of filtering beforehand to properly handle parent / child directories.
        if (originalDir.isDirectory) {
            // Create a temporary directory to move the original directory into as a sibling of the original directory
            // to ensure it resides on the same file system for being able to perform an atomic move.
            val tempDir = createTempDirectory(originalDir.parentFile.toPath(), ".stash").toFile()

            // Use a non-existing directory as the target to ensure the directory can be moved atomically.
            val stashDir = tempDir.resolve(originalDir.name)

            logger.info {
                "Temporarily moving directory from '${originalDir.absolutePath}' to '${stashDir.absolutePath}'."
            }

            originalDir.toPath().moveTo(stashDir.toPath(), StandardCopyOption.ATOMIC_MOVE)

            stashDir
        } else {
            null
        }
    }

    override fun close() {
        // Restore directories in reverse order of stashing to properly handle parent / child directories.
        stashedDirectories.keys.reversed().forEach { originalDir ->
            logger.info("START: close stashed directories: ${originalDir.absolutePath}")

            originalDir.safeDeleteNodeModules()

            stashedDirectories[originalDir]?.let { stashDir ->
                logger.info {
                    "Moving back directory from '${stashDir.absolutePath}' to '${originalDir.absolutePath}'."
                }

                stashDir.toPath().moveTo(originalDir.toPath(), StandardCopyOption.ATOMIC_MOVE)

                // Delete the top-level temporary directory which should be empty now.
                if (!stashDir.parentFile.delete()) {
                    throw IOException("Unable to delete the '${stashDir.parent}' directory.")
                }
            }

            logger.info("END: close stashed directories: ${originalDir.absolutePath}")
        }
    }
}

fun File.safeDeleteNodeModules() {
    if (Os.isWindows) {
        // Note that Kotlin's `Path.deleteRecursively()` extension function cannot delete files on Windows that have the
        // read-only attribute set, so fall back to manually making them writable.
        walkBottomUp().onEnter { !it.isSymbolicLink() }.forEach { it.setWritable(true) }
    }

    // Step 1: Identify and delete symbolic link directories inside node_modules
    val nodeModulesDir = this

    // Walk through the node_modules directory and first delete symbolic link folders.
    // Important: It should not delete the symbolic link folder recursively, otherwise it will delete the actual files from symbolic link folders.
    nodeModulesDir.walkTopDown()
        .filter { it.isSymbolicLink() }
        .forEach { link ->
            val targetPath = link.toPath().toRealPath().toString()
            // Check if the symbolic link points to a directory within the 'packages' directory
            if (targetPath.startsWith(nodeModulesDir.parent)) {
                if (!link.delete()) {
                    logger.warn("Failed to delete symbolic link: ${link.absolutePath}")
                }
            }
        }

    // Step 2: Recursively delete all the remaining contents inside node_modules
    nodeModulesDir.walkTopDown()
        .filter { it != nodeModulesDir } // Ensure we don't try to delete the `node_modules` directory itself
        .forEach { file ->
            if (file.isDirectory) {
                // Delete all contents of the directory
                if (!file.deleteRecursively()) {
                    logger.warn("Failed to delete directory and its contents: ${file.absolutePath}")
                }
            } else if (file.isFile) {
                // Delete individual files
                if (!file.delete()) {
                    logger.warn("Failed to delete file: ${file.absolutePath}")
                }
            }
        }

    // Step 3: Delete the node_modules directory itself if it is empty
    if (!nodeModulesDir.delete()) {
        logger.warn("Failed to delete the node_modules directory")
    }

    // If deleting temp files fails, then retry for one time, if retry fails, skip the temp file deletion as a general business logic in ORT.
    if (exists()) {
        logger.warn("Could not delete file '$absolutePath', retry one time")

        // retry one time
        delete()

        if (exists()) {
            logger.warn("Could not delete file after retry one time: '$absolutePath'")
        }
    }
}

