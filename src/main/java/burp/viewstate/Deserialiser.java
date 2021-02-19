package burp.viewstate;

import burp.IExtensionHelpers;

import static burp.viewstate.ViewState.Version.EMPTY;
import static burp.viewstate.ViewState.Version.UNKNOWN;

public class Deserialiser
{
    private Deserialiser()
    {
    }
    
    public static ViewState deserialise(byte[] base64, IExtensionHelpers helpers)
    {
        byte[] b = helpers.base64Decode(base64);
        
        if (V20Deserialiser.canDeserialise(b))
        {
            try
            {
                return new V20Deserialiser(b, helpers).deserialise();
            }
            catch (Exception ignored)
            {
            }
        }
        
        if (V11Deserialiser.canDeserialise(b))
        {
            try
            {
                return new V11Deserialiser(b, helpers).deserialise();
            }
            catch (Exception ignored)
            {
            }
        }

        ViewState vs;

        if (b.length == 0)
        {
            vs = new ViewState(EMPTY);
        }
        else
        {
            vs = new ViewState(UNKNOWN);
        }

        vs.errorOccurred = true;
        vs.raw = helpers.base64Decode(base64);
        
        return vs;        
    }
}
