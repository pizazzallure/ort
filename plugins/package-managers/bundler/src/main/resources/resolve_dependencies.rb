#!/usr/bin/env ruby

# Copyright (C) 2021 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# License-Filename: LICENSE

# This script mimics the behavior of calling the `bundle lock` CLI command, which resolves a `Gemfile`'s dependencies
# and writes them along with the respective versions to a lockfile [1]. Internally, Bundler tries to find the
# dependencies' `gemspec` files both locally and remotely, and retrieves the respective metadata. However, except for
# the name, version, and transitive dependencies, the Bundler call discards any other metadata. To maintain all
# metadata, this script basically follows the same steps, but then serializes all metadata as YAML for further
# processing by other tools.
#
# [1] https://github.com/rubygems/bundler/blob/35be6d9a603084f719fec4f4028c18860def07f6/lib/bundler/cli/lock.rb#L49-L58

require 'bundler'
require 'yaml'

# Resolve dependencies independently of the Ruby interpreter.
Bundler.settings.set_global(:force_ruby_platform, true)

# This command tries to resolve dependencies that are specified in the Gemfile of the current working directory.
# Explicitly enable resolution of remote `gem` or `git` dependencies. `path` dependencies are still resolved locally.
Bundler.ui.silence {
    Bundler.definition.resolve_remotely!

    # Resolving is triggered lazily, so the below "to_yaml" call might be the place where progress output needs to be
    # silenced in addition to the above "resolve_remotely" call.
    Bundler.definition.specs.map { |spec| spec.to_yaml }.join("\0")
}.tap { |yaml|
    puts yaml
}
