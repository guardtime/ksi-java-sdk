package com.guardtime.ksi.pdu;

import java.util.Date;
import java.util.List;

public interface ExtenderConfiguration {

    Long getMaximumRequests();

    List<String> getParents();

    Date getCalendarFirstTime();

    Date getCalendarLastTime();
}
