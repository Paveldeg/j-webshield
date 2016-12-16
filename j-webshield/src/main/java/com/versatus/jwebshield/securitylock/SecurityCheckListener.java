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
package com.versatus.jwebshield.securitylock;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.versatus.jwebshield.DBHelper;

/**
 * Application Lifecycle Listener implementation class SecurityCheckListener
 * 
 */
public final class SecurityCheckListener implements ServletContextListener,
		HttpSessionListener {
	/**
	 * 
	 */
	private static final long serialVersionUID = -5745385473256396985L;
	private final Logger logger = LoggerFactory
			.getLogger(SecurityCheckListener.class);
	// private String dbJndiName;
	// private String lockSql;
	// private String lockCheckSql;

	private static long timeToLock;

	// private final Timer timer = new Timer();

	public static final long getTimeToLock() {
		return timeToLock;
	}

	public static SecurityLockService securityLockService;

	/**
	 * @see ServletContextEvent#ServletContextEvent(ServletContext)
	 */
	public SecurityCheckListener() {
	}

	/**
	 * @see HttpSessionListener#sessionCreated(HttpSessionEvent)
	 */
	@Override
	public void sessionCreated(HttpSessionEvent se) {
	}

	/**
	 * @see ServletContextListener#contextInitialized(ServletContextEvent)
	 */
	@Override
	public void contextInitialized(ServletContextEvent sce) {
		String file = sce.getServletContext().getInitParameter("configFile");
		if (file != null) {

			try {
				XMLConfiguration config = new XMLConfiguration(file);
				SubnodeConfiguration fields = config
						.configurationAt("securityLock");

				int triesToLock = fields.getInt("triesToLock");
				// lockSql = fields.getString("lockSql");
				// dbJndiName = fields.getString("dbJndiName");
				timeToLock = fields.getInt("timeToLockMin");
				// lockCheckSql = fields.getString("lockCheckSql");

				DBHelper dbh = new DBHelper(config);

				securityLockService = new SecurityLockService(dbh, config);
				securityLockService.setTriesToLock(triesToLock);

				// logger.info("contextInitialized: lockCheckInterval="
				// + lockCheckInterval);
				logger.info("contextInitialized: timeToLock=" + timeToLock);
				// logger.info("contextInitialized: lockSql=" + lockSql);
				// logger.info("contextInitialized: lockCheckSql=" +
				// lockCheckSql);
				// logger.info("contextInitialized: dbJndiName=" + dbJndiName);

			} catch (Exception cex) {
				logger.error("init: unable to load configFile " + file, cex);

			}
		} else {
			logger.error("init: No configFile specified");
		}

		// TimerTask lockCheckTimer = new LockCheckTimerTask();

		// timer.schedule(lockCheckTimer, 10000, (lockCheckInterval * 60 *
		// 1000));
	}

	/**
	 * @see ServletContextListener#contextDestroyed(ServletContextEvent)
	 */
	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		// this.timer.cancel();
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent arg0) {

	}

	class LockCheckTimerTask extends TimerTask {

		@Override
		public void run() {

			logger.debug("LockCheckTimerTask " + new Date().toString());
		}
	}

}
