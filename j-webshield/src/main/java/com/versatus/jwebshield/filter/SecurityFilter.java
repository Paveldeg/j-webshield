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
package com.versatus.jwebshield.filter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.versatus.jwebshield.SecurityConstant;
import com.versatus.jwebshield.SecurityInfo;
import com.versatus.jwebshield.UrlExclusionList;

/**
 * Intercepts requests according to mappings defined in web.xml. When applicable
 * checks if the randomized token in the request matches the token name and
 * value in the token cache stored in the session. If session does not exist for
 * a request - ignores the request. If session exists: 1. Check if URL of the
 * page matches exclusion list defined in the filter config. file (see FAQ) -
 * ignore the request. 2. If randomized token from cache does not match the
 * token received with the request - send error 401 and log a message containing
 * IP address and URL. 3. Compare Referer header from the request to the one
 * stored in the cache if not blank - if no match send error 401 and log a
 * message containing IP address and URL.
 * 
 * @author Versatus Corp.
 */
public class SecurityFilter implements Filter {

	private final Logger logger = LoggerFactory.getLogger(SecurityFilter.class);

	private boolean useCsrfToken = false;
	private String csrfHeaderName;
	private String csrfCookieName;
	private String[] methodExclusionList;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		// Assume its HTTP
		HttpServletRequest httpReq = (HttpServletRequest) request;

		String reqInfo = "J-WebShield Alert: CSRF attack detected! request URL="
				+ httpReq.getRequestURL().toString()
				+ "| from IP address="
				+ httpReq.getRemoteAddr();

		logger.debug("doFilter: IP address=" + httpReq.getRemoteAddr());
		logger.debug("doFilter: pathInfo=" + httpReq.getPathInfo());
		logger.debug("doFilter: queryString=" + httpReq.getQueryString());
		logger.debug("doFilter: requestURL="
				+ httpReq.getRequestURL().toString());
		logger.debug("doFilter: method=" + httpReq.getMethod());
		logger.debug("doFilter: Origin=" + httpReq.getHeader("Origin"));
		logger.info("doFilter: Referer=" + httpReq.getHeader("Referer"));
		logger.info("doFilter: " + csrfHeaderName + "="
				+ httpReq.getHeader(csrfHeaderName));

		UrlExclusionList exclList = (UrlExclusionList) request
				.getServletContext().getAttribute(
						SecurityConstant.CSRF_CHECK_URL_EXCL_LIST_ATTR_NAME);
		HttpSession session = httpReq.getSession(false);
		if (session == null) {
			chain.doFilter(request, response);
			return;
		}

		logger.debug("doFilter: matching " + httpReq.getRequestURI()
				+ " to exclusions list " + exclList.getExclusionMap());

		try {
			if (!exclList.isEmpty()
					&& exclList.isMatch(httpReq.getRequestURI())) {
				chain.doFilter(request, response);
				return;
			}
		} catch (Exception e) {
			logger.error("doFilter", e);
		}
		// check CSRF cookie/header
		boolean csrfHeaderPassed = false;
		String rawCsrfHeaderVal = httpReq.getHeader(csrfHeaderName);
		if (useCsrfToken && StringUtils.isNotBlank(rawCsrfHeaderVal)) {
			String csrfHeader = StringUtils.strip(
					httpReq.getHeader(csrfHeaderName), "\"");
			logger.debug("doFilter: csrfHeader after decoding" + csrfHeader);
			Cookie[] cookies = httpReq.getCookies();
			for (Cookie c : cookies) {
				String name = c.getName();

				if (StringUtils.isNotBlank(csrfCookieName)
						&& csrfCookieName.equals(name)) {

					logger.debug("doFilter: cookie domain=" + c.getDomain()
							+ "|name=" + name + "|value=" + c.getValue()
							+ "|path=" + c.getPath() + "|maxage="
							+ c.getMaxAge() + "|httpOnly=" + c.isHttpOnly());

					logger.debug("doFilter: string comp:"
							+ StringUtils.difference(csrfHeader, c.getValue()));

					if (StringUtils.isNotBlank(csrfHeader)
							&& csrfHeader.equals(c.getValue())) {

						csrfHeaderPassed = true;
						logger.info("Header " + csrfHeaderName
								+ " value matches the cookie " + csrfCookieName);
						break;
					} else {
						logger.info("Header " + csrfHeaderName
								+ " value does not match the cookie "
								+ csrfCookieName);
					}
				}

			}
			// String csrfCookieVal = (String) session
			// .getAttribute(SecurityConstant.CSRFCOOKIE_VALUE_PARAM);
			// if (csrfCookieVal != null && csrfCookieVal.equals(csrfHeader)) {
			// // chain.doFilter(request, response);
			// // return;
			// csrfHeaderPassed = true;
			// } else {
			// // logger.info(reqInfo);
			// // sendSecurityReject(response);
			// }
		}

		if (useCsrfToken && csrfHeaderPassed) {
			chain.doFilter(request, response);
			return;
		}

		// Validate that the salt is in the cache
		Cache<SecurityInfo, SecurityInfo> csrfPreventionSaltCache = (Cache<SecurityInfo, SecurityInfo>) httpReq
				.getSession().getAttribute(
						SecurityConstant.SALT_CACHE_ATTR_NAME);

		if (csrfPreventionSaltCache != null) {
			// Get the salt sent with the request
			String saltName = (String) httpReq.getSession().getAttribute(
					SecurityConstant.SALT_PARAM_NAME);

			logger.debug("doFilter: csrf saltName=" + saltName);

			if (saltName != null) {

				String salt = httpReq.getParameter(saltName);

				logger.debug("doFilter: csrf salt=" + salt);

				if (salt != null) {

					SecurityInfo si = new SecurityInfo(saltName, salt);

					logger.debug("doFilter: csrf token="
							+ csrfPreventionSaltCache.getIfPresent(si));

					SecurityInfo cachedSi = csrfPreventionSaltCache
							.getIfPresent(si);
					if (cachedSi != null) {
						// csrfPreventionSaltCache.invalidate(si);
						if (SecurityTokenFilter.checkReferer) {
							String refHeader = StringUtils
									.defaultString(httpReq.getHeader("Referer"));
							logger.debug("doFilter: refHeader=" + refHeader);
							if (StringUtils.isNotBlank(refHeader)) {
								try {
									URL refUrl = new URL(refHeader);
									refHeader = refUrl.getHost();
								} catch (MalformedURLException mex) {
									logger.debug(
											"doFilter: parsing referer header failed",
											mex);
								}
							}
							if (!cachedSi.getRefererHost().isEmpty()
									&& !refHeader.equalsIgnoreCase(cachedSi
											.getRefererHost())) {
								logger.info("Potential CSRF detected - Referer host does not match orignal! "
										+ refHeader
										+ " != "
										+ cachedSi.getRefererHost());
								sendSecurityReject(response);
							}
						}

						chain.doFilter(request, response);
					} else {
						logger.info(reqInfo);
						sendSecurityReject(response);
					}
				} else if (httpMethodMatch(httpReq.getMethod())) {
					// let flow through
					chain.doFilter(request, response);
				} else {
					logger.info(reqInfo);
					sendSecurityReject(response);
				}
			}
		} else {
			chain.doFilter(request, response);
		}

	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		String file = filterConfig.getInitParameter("configFile");
		if (file != null) {

			try {
				XMLConfiguration config = new XMLConfiguration(file);

				useCsrfToken = config
						.getBoolean(SecurityConstant.USECSRFHEADER_PARAM);
				csrfHeaderName = config
						.getString(SecurityConstant.CSRFHEADERNAME_PARAM);
				csrfCookieName = config
						.getString(SecurityConstant.CSRFCOOKIENAME_PARAM);
				methodExclusionList = config
						.getStringArray("httpMethodExclusions");

				logger.info("init: useCsrfToken=" + useCsrfToken);
				logger.info("init: csrfHeaderName=" + csrfHeaderName);
				logger.info("init: httpMethodExclusions="
						+ Arrays.asList(methodExclusionList));
			} catch (Exception cex) {
				logger.error("init: unable to load configFile " + file, cex);

			}
		} else {
			logger.error("init: No configFile specified");
		}
	}

	@Override
	public void destroy() {
	}

	private void sendSecurityReject(ServletResponse response) {
		try {
			((HttpServletResponse) response)
					.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		} catch (IOException e) {
			// ignore
		}
	}

	private boolean httpMethodMatch(String method) {
		for (String m : methodExclusionList) {
			if (method != null && method.equalsIgnoreCase(m)) {
				return true;
			}
		}
		return false;
	}
}
