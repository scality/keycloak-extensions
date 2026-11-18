package com.scality.keycloak.longLivedToken;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSessionFactory;

public class LongLivedTokenExpiryMetricRefreshTest {

    @Test
    public void a_failed_refresh_does_not_fail_the_caller() {
        KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
        when(factory.create()).thenThrow(new IllegalStateException("database unavailable"));

        assertDoesNotThrow(() -> new LongLivedTokenExpiryMetric().refreshInNewTransaction(factory));
    }
}
