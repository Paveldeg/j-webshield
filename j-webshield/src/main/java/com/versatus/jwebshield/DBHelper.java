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

import java.sql.Connection;
import java.sql.SQLException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DBHelper {
	private final Logger logger = LoggerFactory.getLogger(DBHelper.class);
	private DataSource ds = null;

	public DBHelper(Configuration config) throws Exception {

		try {
			Context initCtx = new InitialContext();
			Context envCtx = (Context) initCtx.lookup("java:comp/env");

			SubnodeConfiguration fields = ((XMLConfiguration) config)
					.configurationAt("securityLock");

			if (envCtx != null) {
				ds = (DataSource) envCtx.lookup(fields.getString("dbJndiName"));
			}
		} catch (javax.naming.NoInitialContextException ne) {

		} catch (Exception e) {
			logger.error("constructor", e);
		}

	}

	public Connection getConnection() throws SQLException {
		Connection conn = null;

		if (ds != null) {
			conn = ds.getConnection();
		}
		return conn;
	}

}
