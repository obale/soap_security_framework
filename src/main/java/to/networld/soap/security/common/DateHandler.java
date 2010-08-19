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
