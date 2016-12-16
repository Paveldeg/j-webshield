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

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.dbutils.BasicRowProcessor;
import org.apache.commons.dbutils.DbUtils;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.BeanHandler;
import org.apache.commons.dbutils.handlers.MapHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.versatus.jwebshield.DBHelper;

public final class SecurityLockService {

	private final Logger logger = LoggerFactory
			.getLogger(SecurityLockService.class);

	private final DBHelper dbHelper;
	private final Configuration config;
	private final static String lockCheckSql = "select * from LOCKS where userid=? or ip=?";
	private final static String insertlockSql = "insert into LOCKS (userid,ip) values(?,?) ON DUPLICATE KEY UPDATE trycounter=trycounter + 1";
	private final static String setlockSql = "update LOCKS set `lock`=?, locktimestamp=CURRENT_TIMESTAMP where userid=? or ip=? ";

	// private final static String delLockSql = "delete from LOCKS where ip=?";
	private final static String resetLockSql = "update LOCKS set trycounter=0, `lock`=false, locktimestamp=null where ip=?";

	private static int triesToLock;

	public final int getTriesToLock() {
		return triesToLock;
	}

	public final void setTriesToLock(int triesToLock) {
		SecurityLockService.triesToLock = triesToLock;
	}

	public SecurityLock processSecurityLock(int userId, String ip)
			throws SecurityLockException {
		QueryRunner run = new QueryRunner();
		Connection conn = null;
		SecurityLock al = null;

		List<Object> params = new ArrayList<Object>(3);

		try {
			conn = dbHelper.getConnection();

			al = checkSecurityLock(userId, ip);

			logger.debug("lockAccount: TriesToLock=" + getTriesToLock());

			int r = 0;

			if (al.getTryCounter() >= getTriesToLock() && !al.isLock()) {
				params.add(true);
				params.add(userId);
				params.add(ip);
				r = run.update(conn, setlockSql, params.toArray());
			} else {
				params.add(userId);
				params.add(ip);
				// params.add(false);
				r = run.update(conn, insertlockSql, params.toArray());
			}

			al = checkSecurityLock(userId, ip);

			logger.debug("lockAccount: response=" + r);

		} catch (SQLException e) {
			logger.error("lockAccount", e);
			logger.debug("lockAccount: ErrorCode=", e.getErrorCode());
			throw new SecurityLockException(
					"Unable to access security lock database", e);
		} finally {

			try {
				DbUtils.close(conn);
			} catch (SQLException e) {
				// ignore
			}
		}
		return al;
	}

	public SecurityLockService(final DBHelper dbHelper,
			final Configuration config) {
		super();
		this.dbHelper = dbHelper;
		this.config = config;
		SubnodeConfiguration fields = ((XMLConfiguration) config)
				.configurationAt("securityLock");
		// this.lockCheckSql = fields.getString("lockCheckSql");
	}

	private SecurityLock checkSecurityLock(int userId, String ip)
			throws SQLException {

		logger.debug("checkAccountLock: userid=" + userId);
		logger.debug("checkAccountLock: ip=" + ip);

		SecurityLock res;
		Object[] params = new Object[] { userId, ip };

		QueryRunner run = new QueryRunner();
		Connection conn = dbHelper.getConnection();
		BeanHandler<SecurityLock> rsh = new BeanHandler(SecurityLock.class) {

			@Override
			public SecurityLock handle(ResultSet rs) throws SQLException {
				SecurityLock brp = null;
				if (rs.first()) {
					brp = new BasicRowProcessor()
							.toBean(rs, SecurityLock.class);
				}
				return brp;
			}
		};

		try {

			res = run.query(conn, lockCheckSql, rsh, params);

			logger.debug("checkAccountLock: response=" + res);

			if (res != null) {
				if (res.isLock()) {
					logger.debug("checkAccountLock: Calendar.getInstance()="
							+ Calendar.getInstance().getTime());
					logger.debug("checkAccountLock: TimeWhenUnlock()="
							+ res.getTimeWhenUnlock());
					logger.debug("checkAccountLock: is time to ulock="
							+ Calendar.getInstance().getTime()
									.after(res.getTimeWhenUnlock()));
					if (Calendar.getInstance().getTime()
							.after(res.getTimeWhenUnlock())) {
						logger.info("unlocking IP " + res.getIp());
						int r = run.update(conn, resetLockSql,
								new Object[] { ip });

						logger.debug("checkAccountLock: reset response=" + r);

						res = run.query(conn, lockCheckSql, rsh, params);

						logger.debug("checkAccountLock: after reset response="
								+ res);
					}
				}

			} else {
				res = new SecurityLock();
				res.setLock(false);
			}

		} finally {

			try {
				DbUtils.close(conn);
			} catch (SQLException e) {
				// ignore
			}
		}

		return res;
	}

	public boolean resetLock(int userId, String ip) throws SQLException {

		QueryRunner run = new QueryRunner();
		Connection conn = dbHelper.getConnection();

		logger.info("resetting lock for IP " + ip);
		int r = run.update(conn, resetLockSql, new Object[] { ip });

		logger.debug("checkAccountLock: reset response=" + r);

		return r > 0;
	}

}
