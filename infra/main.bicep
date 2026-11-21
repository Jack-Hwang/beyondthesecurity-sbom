// BTS-SBOM app service infrastructure (task 15) - a minimal, keyless-by-default deployment.
//
// Scope out (stated honestly, per the course reference output's convention):
//   * self-hosted models, private endpoints / VNet integration, Front Door / WAF, multi-region.
//   * alert rules: the metric names for the App Service health-check state were NOT verified against
//     Azure docs in this environment, so no metric alert is declared here (see RUNBOOK "확인 필요").
//
// Items marked "// 확인 필요" are general-knowledge claims from outside the course material; verify against
// the official Azure docs before provisioning (the brief forbids guessing values it cannot check).
targetScope = 'subscription'

@description('3 required tags: team, week, owner - no defaults, the cost policy refuses untagged resources')
param teamTag string
@description('course week identifier, e.g. w6')
param weekTag string
@description('owner identity for cost and accountability')
param ownerTag string

@description('App Service plan SKU; slots are believed to require at least Standard (S1) - 확인 필요')
@allowed(['S1', 'P1v3', 'P1v2'])
param planSku string = 'S1'

@description('plan capacity: exactly 1, no autoscale (single-writer evidence store, ADR-0019)')
@minValue(1)
@maxValue(1)
param capacity int = 1

param location string = 'koreacentral'
param appName string = 'bts-sbom-app'
param keyVaultName string
param acrName string
param logAnalyticsName string
param appInsightsName string
param imageTag string = 'latest'

var tags = { team: teamTag, week: weekTag, owner: ownerTag }

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    retentionInDays: 30
    sku: { name: 'PerGB2018' }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    // workspace-based Application Insights (the classic one is retired) - 확인 필요
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-identity'
  location: location
  tags: tags
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-06-01-preview' = {
  name: acrName
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false                                   // keyless: pulls go through the managed identity
  }
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, 'AcrPull')
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d') // AcrPull
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: { name: 'standard', family: 'A' }
    enableRbacAuthorization: true                              // no access policies, RBAC only
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    // purgeProtection is irreversible once enabled; the course recommends deletion protection - 확인 필요
    enablePurgeProtection: false
  }
}

resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, 'KeyVaultSecretsUser')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458e-272f-4bf2-b911-bd9b8ee7a8b2') // Key Vault Secrets User
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${appName}-plan'
  location: location
  tags: tags
  sku: { name: planSku, capacity: capacity }                  // capacity 1, 0 autoscale rules anywhere
  properties: { reserved: true }                              // reserved = Linux
}

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: tags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    httpsOnly: true
    minTlsVersion: '1.2'
    ftpsState: 'Disabled'
    healthCheckPath: '/readyz'
    serverFarmId: plan.id
    siteConfig: {
      linuxFxVersion: 'DOCKER|${acr.name}.azurecr.io/bts-sbom-app:${imageTag}'
      alwaysOn: true                                            // capacity 1: no scale-out, so no slot swap warm-up issue
      healthCheckPath: '/readyz'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        { name: 'BTS_SBOM_CLOUD', value: '1' }
        { name: 'WEBSITES_PORT', value: '8800' }
        // Key Vault reference (no literal secret). The OPERATOR creates the secret 'bts-sbom-api-token' in
        // the vault first; the app cannot start authenticated until it exists (fail-closed by design, ADR-0017).
        { name: 'BTS_SBOM_API_TOKEN', value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/bts-sbom-api-token)' }
        { name: 'BTS_SBOM_SOURCE_HOSTS', value: 'github.com,gitlab.com,bitbucket.org' }
        { name: 'BTS_OSS_ALLOWED_HOSTS', value: '${appName}.azurewebsites.net' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
      ]
    }
  }
}

resource slot 'Microsoft.Web/sites/slots@2023-12-01' = {
  parent: app
  name: 'staging'
  location: location
  tags: tags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    httpsOnly: true
    serverFarmId: plan.id
    siteConfig: {
      linuxFxVersion: 'DOCKER|${acr.name}.azurecr.io/bts-sbom-app:${imageTag}'
      healthCheckPath: '/readyz'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
    }
  }
}

// Evidence persistence: primary plan is the container's persistent /home via
// WEBSITES_ENABLE_APP_SERVICE_STORAGE=true (behaviour and limits: 확인 필요). The alternative - a Storage
// account + Azure Files mount - needs the mount's auth model verified (account key vs managed identity,
// whether that collides with the course's "no shared keys" policy) before it may be added here.
// 확인 필요: WEBSITES_ENABLE_APP_SERVICE_STORAGE semantics for custom containers are not verified.
// The app setting is therefore intentionally NOT set in this template; a follow-up adds it after verification,
// together with the chosen storage decision recorded in ADR-0016/0019.

resource budget 'Microsoft.Consumption/budgets@2023-05-01' = {
  // targetScope is 'subscription', so the budget deploys there directly (no scope property needed)
  name: '${appName}-monthly-budget'
  properties: {
    timePeriod: {
      startDate: '2026-12-01'
      endDate: '2027-12-01'
    }
    timeGrain: 'Monthly'
    amount: 50
    category: 'Cost'
    notifications: {
      fifty: { enabled: true, operator: 'GreaterThan', threshold: 50, contactEmails: [] }
      eighty: { enabled: true, operator: 'GreaterThan', threshold: 80, contactEmails: [] }
      hundred: { enabled: true, operator: 'GreaterThan', threshold: 100, contactEmails: [] }
    }
  }
}

output keyVaultTokenSecretName string = 'bts-sbom-api-token'    // the secret the operator creates; the template holds NO value
output appInsightsConnectionString string = appInsights.properties.ConnectionString
