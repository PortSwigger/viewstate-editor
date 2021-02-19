package burp.viewstate;

public class ViewState
{
    public enum Version
    {
        UNKNOWN, V11, V20, EMPTY
    }

    public DeserialisedObject value;
    public Version version;
    public boolean errorOccurred;
    public boolean macEnabled;
    public byte[] raw;
    
    public ViewState(Version version)
    {
        this.version = version;
    }

    @Override
    public String toString()
    {
        if (version == Version.EMPTY)
        {
            return "";
        }
        
        return "\t" + (errorOccurred ? "errors" : ("no errors" + "\t" + (macEnabled ? "macEnabled" : "NOT macEnabled")));
    }
}
