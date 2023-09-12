/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Original sources:
 * http://commons.apache.org/proper/commons-io/apidocs/src-html/org/apache/commons/io/FilenameUtils.html
 * http://commons.apache.org/proper/commons-io/apidocs/src-html/org/apache/commons/io/IOCase.html
 */

package itx.fileserver.services;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;

public final class FileUtils {

    private FileUtils() {
        throw new UnsupportedOperationException("please do not instantiate utility class");
    }

    /**
     * Checks a filename to see if it matches the specified wildcard matcher, always testing case-sensitive.
     * The wildcard matcher uses the characters '?' and '*' to represent a
     * single or multiple (zero or more) wildcard characters.
     * This is the same as often found on Dos/Unix command lines.
     * The check is case-sensitive always.
     *
     * <pre>
     *  wildcardMatch("c.txt", "*.txt")      --&gt; true
     *  wildcardMatch("c.txt", "*.jpg")      --&gt; false
     *  wildcardMatch("a/b/c.txt", "a/b/*")  --&gt; true
     *  wildcardMatch("c.txt", "*.???")      --&gt; true
     *  wildcardMatch("c.txt", "*.????")     --&gt; false
     * </pre>
     *
     * @param filename        the filename to match on
     * @param wildcardMatcher the wildcard string to match against
     * @return true if the filename matches the wildcard string
     */
    public static boolean wildcardMatch(final String filename, final String wildcardMatcher) {
        String matcher = "glob:";

        if (File.separator.equals("\\")) { // window fix
            matcher += wildcardMatcher.replace("/", "\\\\");
        } else { //linux
            matcher += wildcardMatcher;
        }

        PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher(matcher);
        /* Path.of will remove the trailing slash */
        Path path = Path.of(filename);
        if (pathMatcher.matches(path)) {
            return true;
        }
        if (filename.endsWith(FileSystems.getDefault().getSeparator())) {
            pathMatcher = FileSystems.getDefault().getPathMatcher(matcher.replaceAll("/(\\*){0,2}$", ""));
            return pathMatcher.matches(path);
        }
        return false;
    }

    /*expr = Globs.toUnixRegexPattern(input);
} else {
        if (!syntax.equalsIgnoreCase("regex")) {
        throw new UnsupportedOperationException("Syntax '" + syntax + "' not recognized");
        }

        expr = input;
        }

final Pattern pattern = this.compilePathMatchPattern(expr);
        return new PathMatcher() {
public boolean matches(Path path) {
        return pattern.matcher(path.toString()).matches();
        }
        };*/
}
