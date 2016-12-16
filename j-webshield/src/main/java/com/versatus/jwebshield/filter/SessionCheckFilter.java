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
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.versatus.jwebshield.SecurityConstant;
import com.versatus.jwebshield.UrlExclusionList;

/**
 * Servlet Filter implementation class SessionCheckFilter
 */
public class SessionCheckFilter implements Filter {
	private final Logger logger = LoggerFactory
			.getLogger(SessionCheckFilter.class);
	private String redirectPage;
	private String attributeToCheck;
	private boolean send401;

	/**
	 * Default constructor.
	 */
	public SessionCheckFilter() {
	}

	/**
	 * @see Filter#destroy()
	 */
	@Override
	public void destroy() {
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpReq = (HttpServletRequest) request;
		HttpServletResponse httpRes = (HttpServletResponse) response;
		String reqInfo = "J-WebShield Alert: Session check failed! request URL="
				+ httpReq.getRequestURL().toString()
				+ "| from IP address="
				+ httpReq.getRemoteAddr();

		logger.debug("doFilter: RequestURL="
				+ httpReq.getRequestURL().toString());

		UrlExclusionList exclList = (UrlExclusionList) request
				.getServletContext().getAttribute(
						SecurityConstant.SESSION_CHECK_URL_EXCL_LIST_ATTR_NAME);

		try {
			if (!exclList.isEmpty()
					&& exclList.isMatch(httpReq.getRequestURI())) {
				logger.info("doFilter: request ("
						+ httpReq.getRequestURL().toString()
						+ " matches exclusion pattern, skipping session check");
				chain.doFilter(request, response);
				return;
			}
		} catch (Exception e) {
			logger.error("doFilter", e);
		}

		HttpSession session = httpReq.getSession(false);
		logger.debug("doFilter: session=" + session);
		logger.debug("doFilter: session attr. "
				+ attributeToCheck
				+ "="
				+ (session != null ? session.getAttribute(attributeToCheck)
						: ""));

		if (session == null || session.getAttribute(attributeToCheck) == null) {
			if (send401) {
				// TODO this is not working for regular requests, only for WS
				// calls
				httpRes.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			} else {
				logger.info(reqInfo + " redirecting to " + redirectPage);

				RequestDispatcher rd = httpReq
						.getRequestDispatcher(redirectPage);
				if (rd != null) {
					rd.forward(request, response);
				}
				return;
			}

		}

		logger.info("doFilter: session check complete");

		// pass the request along the filter chain
		chain.doFilter(request, response);
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	@Override
	public void init(FilterConfig fConfig) throws ServletException {
		String file = fConfig.getServletContext()
				.getInitParameter("configFile");
		if (file != null) {
			UrlExclusionList urlExList = new UrlExclusionList();
			fConfig.getServletContext().setAttribute(
					SecurityConstant.SESSION_CHECK_URL_EXCL_LIST_ATTR_NAME,
					urlExList);

			try {
				XMLConfiguration config = new XMLConfiguration(file);
				SubnodeConfiguration fields = config
						.configurationAt("sessionCheck");
				List<Object> exclusionList = fields
						.getList("sessionCheckUrlExclusions");
				redirectPage = fields.getString("redirectPage");
				attributeToCheck = fields.getString("attributeToCheck");
				send401 = fields.getBoolean("send401");

				if (exclusionList != null) {
					for (Object obj : exclusionList) {
						urlExList.addUrl((String) obj);
					}
				}
				// logger.info("init: sessionCheckUrlExclusions=" +
				// exclusionList);
				logger.info("init: sessionCheckUrlExclusionsList=" + urlExList);
				logger.info("init: redirectPage=" + redirectPage);

			} catch (Exception cex) {
				logger.error("init: unable to load configFile " + file, cex);

			}
		} else {
			logger.error("init: No configFile specified");
		}

	}

}
