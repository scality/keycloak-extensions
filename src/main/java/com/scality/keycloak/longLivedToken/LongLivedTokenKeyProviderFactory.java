package com.scality.keycloak.longLivedToken;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class LongLivedTokenKeyProviderFactory implements KeyProviderFactory<LongLivedTokenKeyProvider> {
    static final String ID = "long-lived-tokens";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property(Attributes.PRIORITY_PROPERTY)
            .property(Attributes.ENABLED_PROPERTY)
            .build();

    @Override
    public LongLivedTokenKeyProvider create(KeycloakSession session, ComponentModel model) {
        return new LongLivedTokenKeyProvider(session, model);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Public keys of the long-lived tokens that are neither revoked nor expired."
                + " Disabling this provider makes every long-lived token of the realm unverifiable.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    // A component an admin disabled is left as it is. The id is derived from the realm, so a
    // concurrent first issuance fails on the duplicate instead of publishing every key twice.
    static void ensureComponent(RealmModel realm) {
        boolean exists = realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .anyMatch(component -> ID.equals(component.getProviderId()));
        if (exists) {
            return;
        }
        ComponentModel component = new ComponentModel();
        component.setId(UUID.nameUUIDFromBytes((ID + ":" + realm.getId()).getBytes(StandardCharsets.UTF_8)).toString());
        component.setName(ID);
        component.setParentId(realm.getId());
        component.setProviderId(ID);
        component.setProviderType(KeyProvider.class.getName());
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Attributes.PRIORITY_KEY, "0");
        config.putSingle(Attributes.ENABLED_KEY, "true");
        component.setConfig(config);
        realm.addComponentModel(component);
    }
}
