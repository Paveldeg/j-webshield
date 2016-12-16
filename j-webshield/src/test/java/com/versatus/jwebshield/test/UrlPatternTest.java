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
package com.versatus.jwebshield.test;

import junit.framework.TestCase;

import org.apache.commons.lang3.time.StopWatch;

import com.versatus.jwebshield.UrlPatternMatcher;

/**
 * 
 */

/**
 * @author Versatus Corp.
 * 
 */
public class UrlPatternTest extends TestCase {

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testMatches() {
		String[] testUrls = { "/ProfileResp.jsp", "my.js", "/myapp/test.htm",
				"/myapp" };
		String[] patterns = { "*/test.htm", "/test.htm", "*.js",
				"/servlet/casSSO.htm/*", "*.htm", "*.html", "/myapp/*",
				"/myapp", "/myapp/test.htm", "/servlet", "/servlet/*", "/", "" };

		StopWatch sw = new StopWatch();
		UrlPatternMatcher urlMatcher = new UrlPatternMatcher();
		sw.start();
		for (String ins : testUrls) {
			for (String s : patterns) {
				try {
					System.out.println(urlMatcher.matches(ins, s));
				} catch (Exception e) {

					e.printStackTrace();
				}
			}
		}
		sw.stop();
		System.out.println("Average match time for " + patterns.length
				* testUrls.length + " patterns: " + sw.getTime()
				/ (patterns.length * testUrls.length) + " ns");
	}
}
