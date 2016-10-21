package com.guardtime.ksi.publication.adapter;

import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.TestUtil.PUBLICATIONS_FILE_27_07_2016;

public class AbstractPublicationsFileClientAdapterTest {

    protected KSIPublicationsFileClient mockedPublicationsFileClient;
    protected Future mockedPublicationsFileResponse;
    protected PKITrustStore mockedTrustStore;

    @BeforeMethod
    public void setUp() throws Exception {
        mockedTrustStore = Mockito.mock(PKITrustStore.class);
        Mockito.when(mockedTrustStore.isTrusted(Mockito.any(X509Certificate.class), Mockito.any(Store.class))).thenReturn(true);

        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        mockedPublicationsFileResponse = Mockito.mock(Future.class);
        Mockito.when(mockedPublicationsFileResponse.getResult()).thenReturn(ByteBuffer.wrap(Util.toByteArray(load(PUBLICATIONS_FILE_27_07_2016))));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(mockedPublicationsFileResponse);
    }


}
