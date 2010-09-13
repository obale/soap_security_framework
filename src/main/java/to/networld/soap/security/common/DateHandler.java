/**
 * SOAP Security Framework
 *
 * Copyright (C) 2010 by Networld Project
 * Written by Alex Oberhauser <oberhauseralex@networld.to>
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>
 */

package to.networld.soap.security.common;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * @author Alex Oberhauser
 *
 */
public class DateHandler {
	
	public static String getDateString(Calendar _date, int _minutesOffset) {
		if ( _minutesOffset != 0) {
	        _date.set(Calendar.MINUTE, _date.get(Calendar.MINUTE) + _minutesOffset);
		}
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		return df.format(_date.getTime());
	}
	
}
