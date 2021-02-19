package burp;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.registerMessageEditorTabFactory((controller, editable) -> new ViewStateTab(callbacks, controller, editable));
        callbacks.setExtensionName("ViewState editor");
    }
}