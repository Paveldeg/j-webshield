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

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.time.DateUtils;

public class SecurityLock {

	private String userId;
	private String ip;
	private boolean lock;
	private int tryCounter;
	private int id;
	private Date timestamp;
	private Date lockTimestamp;
	private int lockTimeMin;

	public final Date getLockTimestamp() {
		return lockTimestamp;
	}

	public final void setLockTimestamp(Date lockTimestamp) {
		this.lockTimestamp = lockTimestamp;
	}

	public final int getLockTimeMin() {
		return lockTimeMin;
	}

	public final void setLockTimeMin(int lockTimeMin) {
		this.lockTimeMin = lockTimeMin;
	}

	public final Date getTimestamp() {
		return timestamp;
	}

	public final void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}

	public final String getUserId() {
		return userId;
	}

	public final void setUserId(String userId) {
		this.userId = userId;
	}

	public final String getIp() {
		return ip;
	}

	public final void setIp(String ip) {
		this.ip = ip;
	}

	public final boolean isLock() {
		return lock;
	}

	public final void setLock(boolean lock) {
		this.lock = lock;
	}

	public final int getTryCounter() {
		return tryCounter;
	}

	public final void setTryCounter(int tryCounter) {
		this.tryCounter = tryCounter;
	}

	public final int getId() {
		return id;
	}

	public final void setId(int id) {
		this.id = id;
	}

	public Date getTimeWhenUnlock() {
		Date res = null;
		Calendar cal = Calendar.getInstance();
		if (getLockTimestamp() != null) {
			long lockCreated = getLockTimestamp().getTime();

			long remTime = lockCreated
					+ (SecurityCheckListener.getTimeToLock() * 60 * 1000);
			if (remTime > 0) {
				cal.setTimeInMillis(remTime);
				res = cal.getTime();
			}
		}
		return res;
	}

	public SecurityLock() {
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this);
	}

}
