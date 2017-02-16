/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package com.guardtime.ksi.trust;

import com.guardtime.ksi.exceptions.KSIException;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * This class implements the {@link CertSelector} and can be used to search certificates by certificate subject DN. If
 * input contains multiple RDN values then all the values must be present inside certificate subject DN.
 */
public class X509CertificateSubjectRdnSelector implements CertSelector {

    private RDN[] rdnArray;

    /**
     * Parses the passed is string and uses values to search the certificate. If null then {@link
     * CertSelector#match(Certificate)} method returns true for every {@link X509Certificate} object.
     *
     * @param rdnString
     *         rdn string to parse
     */
    public X509CertificateSubjectRdnSelector(String rdnString) throws KSIException {
        if (rdnString == null || rdnString.length() == 0) {
            throw new KSIException("Invalid input parameter. RDN string must be present");
        }
        this.rdnArray = BCStyle.INSTANCE.fromString(rdnString);
        ensureSingleRdnValues(rdnArray);
    }

    /**
     * Creates new instance of {@link X509CertificateSubjectRdnSelector} with specified certificate subject DN values.
     *
     * @param rdnArray
     *         RDN values to use. If null then {@link CertSelector#match(Certificate)} method returns true for every
     *         {@link X509Certificate} object.
     */
    public X509CertificateSubjectRdnSelector(RDN[] rdnArray) throws KSIException {
        if (rdnArray == null || rdnArray.length == 0) {
            throw new KSIException("Invalid input parameter.At least one RDN must be present");
        }
        ensureSingleRdnValues(rdnArray);
        this.rdnArray = rdnArray;
    }

    public boolean match(Certificate cert) {
        if (!(cert instanceof X509Certificate)) {
            return false;
        }
        if (rdnArray == null) {
            return true;
        }
        try {
            X500Name x500name = getX500SubjectName((X509Certificate) cert);
            boolean ok = true;
            for (RDN rdn : rdnArray) {
                AttributeTypeAndValue expectedTypeAndValue = rdn.getFirst();

                ok = ok && contains(x500name, expectedTypeAndValue);
            }
            return ok;
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    X500Name getX500SubjectName(X509Certificate cert) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(cert).getSubject();
    }

    private boolean contains(X500Name name, AttributeTypeAndValue expectedTypeAndValue) {
        RDN[] certificateRdnValues = name.getRDNs(expectedTypeAndValue.getType());
        return checkArrayOfRdn(certificateRdnValues, expectedTypeAndValue);
    }

    private boolean checkArrayOfRdn(RDN[] certificateRdnValues, AttributeTypeAndValue expectedTypeAndValue) {
        boolean containsCorrectValues = true;
        for (RDN certRDN : certificateRdnValues) {
            if(!checkRdn(certRDN, expectedTypeAndValue)) {
                containsCorrectValues = false;
                break;
            }
        }
        return containsCorrectValues;
    }

    private boolean checkRdn(RDN certRDN, AttributeTypeAndValue expectedTypeAndValue) {
        String expectedValue = IETFUtils.valueToString(expectedTypeAndValue.getValue());
        boolean constraintFound = false;
        AttributeTypeAndValue[] typesAndValues = certRDN.getTypesAndValues();
        for (AttributeTypeAndValue typesAndValue : typesAndValues) {
            if (typesAndValue.getType().equals(expectedTypeAndValue.getType())) {
                String actualValue = IETFUtils.valueToString(typesAndValue.getValue());
                if (actualValue.equals(expectedValue)) {
                    constraintFound = true;
                } else {
                    constraintFound = false;
                    break;
                }
            }
        }

        return constraintFound;
    }

    public Object clone() {
        try {
            return new X509CertificateSubjectRdnSelector(rdnArray);
        } catch (KSIException e) {
            throw new Error("X509CertificateSubjectRdnSelector cloning failed", e);
        }
    }

    private void ensureSingleRdnValues(RDN[] rdnArray) throws KSIException {
        for (RDN rdn : rdnArray) {
            if (rdn.isMultiValued()) {
                throw new KSIException("Multi-valued certificate constraints aren't supported");
            }
        }

    }

}
