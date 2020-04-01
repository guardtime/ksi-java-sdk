package com.guardtime.ksi.pdu;

import com.guardtime.ksi.service.ConfigurationListener;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

public class PduFactoryProviderTest {
    private static ConfigurationListener<AggregatorConfiguration> aggrConfListener = Mockito.mock(ConfigurationListener.class);
    private static ConfigurationListener<ExtenderConfiguration> extConfListener = Mockito.mock(ConfigurationListener.class);

    @Test
    public void testGetPduFactoryProvider_OK(){
        PduFactory factory = PduFactoryProvider.get(PduVersion.V2);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
           expectedExceptionsMessageRegExp = "Invalid PDU version 'V1'. Allowed values are: V2")
    public void testGetPduFactoryProvider_DeprecatedInput(){
        PduFactory factory = PduFactoryProvider.get(PduVersion.V1);
    }

    @Test
    public void testFactoryProviderGetWithAggrConfListener_OK(){
        PduFactory factory = PduFactoryProvider.withAggregatorConfListener(PduVersion.V2, aggrConfListener);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Invalid PDU version 'V1'. Allowed values are: V2")
    public void testFactoryProviderGetWithAggrConfListener_PduVersionDeprecated(){
        PduFactory factory = PduFactoryProvider.withAggregatorConfListener(PduVersion.V1, aggrConfListener);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test
    public void testFactoryProviderGetWithNullAggrConfListener_OK(){
        PduFactory factory = PduFactoryProvider.withAggregatorConfListener(PduVersion.V2, null);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test
    public void testFactoryProviderGetWithExtConfListener_OK(){
        PduFactory factory = PduFactoryProvider.withExtenderConfListener(PduVersion.V2, extConfListener);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Invalid PDU version 'V1'. Allowed values are: V2")
    public void testFactoryProviderGetWithExtConfListener_PduVersionDeprecated(){
        PduFactory factory = PduFactoryProvider.withExtenderConfListener(PduVersion.V1, extConfListener);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }

    @Test
    public void testFactoryProviderGetWithNullExtConfListener_OK(){
        PduFactory factory = PduFactoryProvider.withExtenderConfListener(PduVersion.V2, null);
        Assert.assertNotNull(factory, "Returned factory is null.");
    }
}
