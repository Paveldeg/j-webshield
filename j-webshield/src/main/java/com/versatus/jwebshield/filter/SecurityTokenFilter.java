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
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.TimeUnit;

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
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.versatus.jwebshield.SecurityConstant;
import com.versatus.jwebshield.SecurityInfo;
import com.versatus.jwebshield.UrlExclusionList;

/**
 * Intercepts requests to UI pages according to mappings defined in web.xml.
 * When applicable sets a randomized token to the request to be used by
 * anti-CSRF script on the target page. If session does not exist for a request
 * - ignores the request. If session exists: 1. Check if URL of the page matches
 * exclusion list defined in the filter config. file (see FAQ) - ignore the
 * request. 2. If randomized token cache does not exist in the session - create
 * one and add a new token as a request attribute under name
 * SecurityConstant.SALT_CACHE_ATTR_NAME. The token name is unique to the
 * session. Also stores Referer header from the request when not blank.
 * 
 * @author Versatus Corp.
 */
public class SecurityTokenFilter implements Filter {

	private final Logger logger = LoggerFactory
			.getLogger(SecurityTokenFilter.class);
	private int tokenTimeout = 1800;
	public static boolean checkReferer = false;
	public static String csrfCookieName;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		HttpServletRequest httpReq = (HttpServletRequest) request;
		HttpServletResponse httpRes = (HttpServletResponse) response;
		UrlExclusionList exclList = (UrlExclusionList) request
				.getServletContext().getAttribute(
						SecurityConstant.CSRF_CHECK_URL_EXCL_LIST_ATTR_NAME);

		logger.debug("doFilter: request from IP address="
				+ httpReq.getRemoteAddr());

		if (httpReq.getSession(false) == null) {
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

		// Check the user session for the salt cache, if none is present we
		// create one
		Cache<SecurityInfo, SecurityInfo> csrfPreventionSaltCache = (Cache<SecurityInfo, SecurityInfo>) httpReq
				.getSession().getAttribute(
						SecurityConstant.SALT_CACHE_ATTR_NAME);

		if (csrfPreventionSaltCache == null) {
			if (tokenTimeout == -1) {
				csrfPreventionSaltCache = CacheBuilder.newBuilder()
						.maximumSize(1000).build();
			} else {
				csrfPreventionSaltCache = CacheBuilder.newBuilder()
						.maximumSize(1000)
						.expireAfterAccess(tokenTimeout, TimeUnit.SECONDS)
						.build();
			}

			httpReq.getSession().setAttribute(
					SecurityConstant.SALT_CACHE_ATTR_NAME,
					csrfPreventionSaltCache);

			String nameSalt = RandomStringUtils.random(10, 0, 0, true, true,
					null, new SecureRandom());
			httpReq.getSession().setAttribute(SecurityConstant.SALT_PARAM_NAME,
					nameSalt);
		}

		// Generate the salt and store it in the users cache
		String salt = RandomStringUtils.random(20, 0, 0, true, true, null,
				new SecureRandom());

		String saltNameAttr = (String) httpReq.getSession().getAttribute(
				SecurityConstant.SALT_PARAM_NAME);
		SecurityInfo si = new SecurityInfo(saltNameAttr, salt);

		if (SecurityTokenFilter.checkReferer) {
			String refHeader = StringUtils.defaultString(httpReq
					.getHeader("Referer"));
			logger.debug("doFilter: refHeader=" + refHeader);
			if (StringUtils.isNotBlank(refHeader)) {
				try {
					URL refUrl = new URL(refHeader);
					refHeader = refUrl.getHost();
				} catch (MalformedURLException mex) {
					logger.debug("doFilter: parsing referer header failed", mex);
				}
			}

			si.setRefererHost(refHeader);
		}

		logger.debug("doFilter: si=" + si.toString());

		csrfPreventionSaltCache.put(si, si);

		// Add the salt to the current request so it can be used
		// by the page rendered in this request
		httpReq.setAttribute(SecurityConstant.SALT_ATTR_NAME, si);

		// set CSRF cookie
		HttpSession session = httpReq.getSession(false);
		if (session != null && StringUtils.isNotBlank(csrfCookieName)) {

			if (logger.isDebugEnabled()) {
				Cookie[] cookies = httpReq.getCookies();
				// boolean cookiePresent = false;
				for (Cookie c : cookies) {
					String name = c.getName();
					logger.debug("doFilter: cookie domain=" + c.getDomain()
							+ "|name=" + name + "|value=" + c.getValue()
							+ "|path=" + c.getPath() + "|maxage="
							+ c.getMaxAge() + "|httpOnly=" + c.isHttpOnly());
					// if (csrfCookieName.equals(name)) {
					// cookiePresent = true;
					// break;
					// }
				}
			}
			// if (!cookiePresent) {
			byte[] hashSalt = new byte[32];
			SecureRandom sr = new SecureRandom();
			sr.nextBytes(hashSalt);

			String csrfHash = RandomStringUtils.random(64, 0, 0, true, true,
					null, sr);

			Cookie c = new Cookie(csrfCookieName, csrfHash);
			c.setMaxAge(1800);
			c.setSecure(false);
			c.setPath(httpReq.getContextPath());
			c.setHttpOnly(false);
			httpRes.addCookie(c);
			// session.setAttribute(SecurityConstant.CSRFCOOKIE_VALUE_PARAM,
			// hashStr);
			// }
		}

		chain.doFilter(request, response);
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

		String file = filterConfig.getInitParameter("configFile");
		if (file != null) {
			UrlExclusionList urlExList = new UrlExclusionList();
			filterConfig.getServletContext().setAttribute(
					SecurityConstant.CSRF_CHECK_URL_EXCL_LIST_ATTR_NAME,
					urlExList);

			try {
				XMLConfiguration config = new XMLConfiguration(file);
				List<Object> exclusionList = config.getList("urlExclusions");
				tokenTimeout = config.getInteger("tokenTimeout", 1800);
				checkReferer = config.getBoolean("checkReferer", true);
				csrfCookieName = config
						.getString(SecurityConstant.CSRFCOOKIENAME_PARAM);

				if (exclusionList != null) {
					for (Object obj : exclusionList) {
						urlExList.addUrl((String) obj);
					}
				}
				logger.info("init: exclusionList=" + exclusionList);
				logger.info("init: urlExList=" + urlExList);
				logger.info("init: csrfCookieName=" + csrfCookieName);
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
}
