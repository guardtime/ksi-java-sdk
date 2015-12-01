package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.tlv.TLVElement;

import java.util.ArrayList;
import java.util.List;

public class PublicationsFileOrderVerifier {
    private static final List<Integer> VALID_ORDER = new ArrayList<Integer>() {
        {
            add(0x701); // pub_header
            add(0x702); // cert_rec
            add(0x703); // pub_rec
            add(0x704); // signature
        }
    };

    public static Boolean verifyOrder(List<TLVElement> elements) {
        OrderState os = new OrderState(VALID_ORDER);
        for (TLVElement elem : elements) {
            if (!os.step(elem.getType())) {
                return false;
            }
        }
        return true;
    }

    private static class OrderState {
        private List<Integer> orderList;

        public OrderState(List<Integer> order) {
            this.orderList = new ArrayList<Integer>(order);
        }

        public Boolean step(int value) {
            if (orderList.contains(value)) {
                int index = orderList.indexOf(value);
                this.orderList = orderList.subList(index, orderList.size());
                return true;
            } else {
                return false;
            }
        }
    }
}
