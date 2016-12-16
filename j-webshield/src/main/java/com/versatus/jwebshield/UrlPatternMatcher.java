/*
 * This file is part of J-WebShield framework.

    J-WebShield framework is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    J-WebShield framework is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with J-WebShield framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.versatus.jwebshield;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches a pattern in a request URL. Pattern syntax attempts to follow Java
 * servlet specification. Examples: *.htm - matches extension, /servlet/* -
 * matches path, test.htm - matches a page
 * 
 * @author Versatus Corp.
 * 
 */
public class UrlPatternMatcher {

	private final Logger logger = LoggerFactory
			.getLogger(UrlPatternMatcher.class);

	/**
	 * Match a URL against a pattern.
	 * 
	 * @param url
	 *            String
	 * @param pattern
	 *            String
	 * @return boolean
	 * @throws Exception
	 */
	public boolean matches(String url, String pattern) throws Exception {

		boolean result = false;

		logger.debug("matches: input - url=" + url + " | pattern=" + pattern);

		if (pattern == null || url == null) {
			throw new Exception("Input parameter(s) are blank!");
		}

		Pattern p;
		if (pattern.contains("*")) {
			p = Pattern.compile(pattern.replace("*", "").replace("/", "\\/")
					+ "$");

		} else if (pattern.equalsIgnoreCase("/")) {
			p = Pattern.compile(pattern.replace("/", "\\/"));
		} else {
			p = Pattern.compile(pattern.replace(".", "\\.").replace("/", "\\/")
					+ "$");
		}

		Matcher matcher = p.matcher(url);

		logger.debug("matches: Original pattern=" + pattern + " | regex="
				+ p.pattern());

		while (matcher.find()) {
			result = true;
			logger.debug("matches: group=" + matcher.group());
		}
		logger.debug("Matching " + pattern + " against " + url + " | result="
				+ result);

		return result;

	}

}
