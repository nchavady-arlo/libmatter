#include "MinimalDataModelProvider.h"
#include <app/data-model-provider/ActionReturnStatus.h>
#include <lib/core/CHIPError.h>

namespace chip {
namespace app {

using Protocols::InteractionModel::Status;
using namespace chip::app::DataModel;
using namespace chip::Protocols::InteractionModel;
// Stub provider that satisfies the factory requirements during initialization.
// Once the InteractionModelEngine is available, a proper provider can be set via
// InteractionModelEngine::SetDataModelProvider()
class StubDataModelProvider : public DataModel::Provider
{
public:
    CHIP_ERROR Shutdown() override { return CHIP_NO_ERROR; }
    
    CHIP_ERROR Endpoints(ReadOnlyBufferBuilder<app::DataModel::EndpointEntry> & builder) override
    {
        return CHIP_NO_ERROR;  // Empty endpoint list
    }
    
    CHIP_ERROR SemanticTags(EndpointId endpointId, ReadOnlyBufferBuilder<SemanticTag> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR DeviceTypes(EndpointId endpointId, ReadOnlyBufferBuilder<app::DataModel::DeviceTypeEntry> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR EventInfo(const app::ConcreteEventPath & path, app::DataModel::EventEntry & eventInfo) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR ClientClusters(EndpointId endpointId, ReadOnlyBufferBuilder<ClusterId> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR ServerClusters(EndpointId endpointId, ReadOnlyBufferBuilder<app::DataModel::ServerClusterEntry> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR Attributes(const app::ConcreteClusterPath & path,
                          ReadOnlyBufferBuilder<app::DataModel::AttributeEntry> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR GeneratedCommands(const app::ConcreteClusterPath & path, ReadOnlyBufferBuilder<CommandId> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    CHIP_ERROR AcceptedCommands(const app::ConcreteClusterPath & path,
                                ReadOnlyBufferBuilder<app::DataModel::AcceptedCommandEntry> & builder) override
    {
        return CHIP_ERROR_NO_ENDPOINT;
    }
    
    void ListAttributeWriteNotification(const app::ConcreteAttributePath & aPath,
                                        app::DataModel::ListWriteOperation opType) override
    {
        // No-op for stub provider
    }
    
    void Temporary_ReportAttributeChanged(const app::AttributePathParams & path) override
    {
        // No-op for stub provider
    }
    
    ActionReturnStatus ReadAttribute(const app::DataModel::ReadAttributeRequest & request,
                                     app::AttributeValueEncoder & encoder) override
    {
        return ActionReturnStatus(Status::UnsupportedEndpoint);
    }
    
    ActionReturnStatus WriteAttribute(const app::DataModel::WriteAttributeRequest & request,
                                      app::AttributeValueDecoder & decoder) override
    {
        return ActionReturnStatus(Status::UnsupportedEndpoint);
    }
    
    std::optional<ActionReturnStatus> InvokeCommand(const app::DataModel::InvokeRequest & request,
                                                    chip::TLV::TLVReader & input_arguments,
                                                    app::CommandHandler * handler) override
    {
        return ActionReturnStatus(Status::UnsupportedEndpoint);
    }
};

static StubDataModelProvider gStubProvider;

DataModel::Provider * MinimalDataModelProviderInstance()
{
    // Return the stub provider that satisfies the factory's initialization requirements
    // This is a minimal provider suitable for controller applications.
    return &gStubProvider;
}

} // namespace app
} // namespace chip

