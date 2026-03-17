#pragma once

#include <app/data-model-provider/Provider.h>

namespace chip {
namespace app {

/// Gets an instance of a global minimal data model provider
/// This uses the EmptyProvider from Matter's testing utilities, which is a
/// lightweight, minimal provider for controller applications that don't need 
/// cluster-specific data model handling. It returns "UnsupportedEndpoint" for
/// most endpoint operations since controllers don't need to expose endpoints.
DataModel::Provider * MinimalDataModelProviderInstance();

} // namespace app
} // namespace chip
