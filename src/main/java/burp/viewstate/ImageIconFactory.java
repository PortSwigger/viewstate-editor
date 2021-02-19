package burp.viewstate;

import burp.viewstate.DeserialisedObject.DeserialisedObjectType;
import burp.viewstate.transcoder.SvgTranscoder;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscodingHints;

import javax.swing.*;
import java.awt.image.BufferedImage;
import java.util.function.Supplier;

import static org.apache.batik.anim.dom.SVGDOMImplementation.getDOMImplementation;
import static org.apache.batik.transcoder.SVGAbstractTranscoder.KEY_HEIGHT;
import static org.apache.batik.transcoder.XMLAbstractTranscoder.*;
import static org.apache.batik.util.SVGConstants.SVG_NAMESPACE_URI;
import static org.apache.batik.util.SVGConstants.SVG_SVG_TAG;

public class ImageIconFactory
{
    // light icons
    // green
    private static final Supplier<ImageIcon> LIGHT_ICON_INT_16 = () -> getSvgIcon("/images/light/vs_int16.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_INT_32 = () -> getSvgIcon("/images/light/vs_int.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_BYTE = () -> getSvgIcon("/images/light/vs_byte.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_CHAR = () -> getSvgIcon("/images/light/vs_char.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_STRING = () -> getSvgIcon("/images/light/vs_string.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_DATETIME = () -> getSvgIcon("/images/light/vs_datetime.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_DOUBLE = () -> getSvgIcon("/images/light/vs_double.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_FLOAT = () -> getSvgIcon("/images/light/vs_float.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_COLOR = () -> getSvgIcon("/images/light/vs_color.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_ENUM = () -> getSvgIcon("/images/light/vs_enum.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_TYPE = () -> getSvgIcon("/images/light/vs_type.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_UNIT = () -> getSvgIcon("/images/light/vs_unit.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_OBJECT = () -> getSvgIcon("/images/light/vs_object.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_BOOLEAN = () -> getSvgIcon("/images/light/vs_boolean.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_HASHTABLE_PAIR = () -> getSvgIcon("/images/light/vs_hashtablepair.svg");

    // blue
    private static final Supplier<ImageIcon> LIGHT_ICON_PAIR = () -> getSvgIcon("/images/light/vs_pair.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_TRIPLET = () -> getSvgIcon("/images/light/vs_triplet.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_ARRAY = () -> getSvgIcon("/images/light/vs_array.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_LIST = () -> getSvgIcon("/images/light/vs_list.svg");
    private static final Supplier<ImageIcon> LIGHT_ICON_HASHTABLE = () -> getSvgIcon("/images/light/vs_hashtable.svg");

    // black
    private static final Supplier<ImageIcon> LIGHT_ICON_NULL = () -> getSvgIcon("/images/light/vs_null.svg");

    // red
    private static final Supplier<ImageIcon> LIGHT_ICON_ERROR = () -> getSvgIcon("/images/light/vs_error.svg");


    // dark icons
    // green
    private static final Supplier<ImageIcon> DARK_ICON_INT_16 = () -> getSvgIcon("/images/dark/vs_int16.svg");
    private static final Supplier<ImageIcon> DARK_ICON_INT_32 = () -> getSvgIcon("/images/dark/vs_int.svg");
    private static final Supplier<ImageIcon> DARK_ICON_BYTE = () -> getSvgIcon("/images/dark/vs_byte.svg");
    private static final Supplier<ImageIcon> DARK_ICON_CHAR = () -> getSvgIcon("/images/dark/vs_char.svg");
    private static final Supplier<ImageIcon> DARK_ICON_STRING = () -> getSvgIcon("/images/dark/vs_string.svg");
    private static final Supplier<ImageIcon> DARK_ICON_DATETIME = () -> getSvgIcon("/images/dark/vs_datetime.svg");
    private static final Supplier<ImageIcon> DARK_ICON_DOUBLE = () -> getSvgIcon("/images/dark/vs_double.svg");
    private static final Supplier<ImageIcon> DARK_ICON_FLOAT = () -> getSvgIcon("/images/dark/vs_float.svg");
    private static final Supplier<ImageIcon> DARK_ICON_COLOR = () -> getSvgIcon("/images/dark/vs_color.svg");
    private static final Supplier<ImageIcon> DARK_ICON_ENUM = () -> getSvgIcon("/images/dark/vs_enum.svg");
    private static final Supplier<ImageIcon> DARK_ICON_TYPE = () -> getSvgIcon("/images/dark/vs_type.svg");
    private static final Supplier<ImageIcon> DARK_ICON_UNIT = () -> getSvgIcon("/images/dark/vs_unit.svg");
    private static final Supplier<ImageIcon> DARK_ICON_OBJECT = () -> getSvgIcon("/images/dark/vs_object.svg");
    private static final Supplier<ImageIcon> DARK_ICON_BOOLEAN = () -> getSvgIcon("/images/dark/vs_boolean.svg");
    private static final Supplier<ImageIcon> DARK_ICON_HASHTABLE_PAIR = () -> getSvgIcon("/images/dark/vs_hashtablepair.svg");

    // blue
    private static final Supplier<ImageIcon> DARK_ICON_PAIR = () -> getSvgIcon("/images/dark/vs_pair.svg");
    private static final Supplier<ImageIcon> DARK_ICON_TRIPLET = () -> getSvgIcon("/images/dark/vs_triplet.svg");
    private static final Supplier<ImageIcon> DARK_ICON_ARRAY = () -> getSvgIcon("/images/dark/vs_array.svg");
    private static final Supplier<ImageIcon> DARK_ICON_LIST = () -> getSvgIcon("/images/dark/vs_list.svg");
    private static final Supplier<ImageIcon> DARK_ICON_HASHTABLE = () -> getSvgIcon("/images/dark/vs_hashtable.svg");

    // light grey
    private static final Supplier<ImageIcon> DARK_ICON_NULL = () -> getSvgIcon("/images/dark/vs_null.svg");

    // red
    private static final Supplier<ImageIcon> DARK_ICON_ERROR = () -> getSvgIcon("/images/dark/vs_error.svg");

    public static ImageIcon getIcon(DeserialisedObjectType type, boolean isLightTheme)
    {
        switch (type)
        {
            case INT16:
                return isLightTheme ? LIGHT_ICON_INT_16.get() : DARK_ICON_INT_16.get();
            case INT32:
                return isLightTheme ? LIGHT_ICON_INT_32.get() : DARK_ICON_INT_32.get();
            case BYTE:
                return isLightTheme ? LIGHT_ICON_BYTE.get() : DARK_ICON_BYTE.get();
            case CHAR:
                return isLightTheme ? LIGHT_ICON_CHAR.get() : DARK_ICON_CHAR.get();
            case STRING:
                return isLightTheme ? LIGHT_ICON_STRING.get() : DARK_ICON_STRING.get();
            case DATETIME:
                return isLightTheme ? LIGHT_ICON_DATETIME.get() : DARK_ICON_DATETIME.get();
            case DOUBLE:
                return isLightTheme ? LIGHT_ICON_DOUBLE.get() : DARK_ICON_DOUBLE.get();
            case FLOAT:
                return isLightTheme ? LIGHT_ICON_FLOAT.get() : DARK_ICON_FLOAT.get();
            case COLOR:
                return isLightTheme ? LIGHT_ICON_COLOR.get() : DARK_ICON_COLOR.get();
            case ENUM:
                return isLightTheme ? LIGHT_ICON_ENUM.get() : DARK_ICON_ENUM.get();
            case TYPE:
                return isLightTheme ? LIGHT_ICON_TYPE.get() : DARK_ICON_TYPE.get();
            case UNIT:
                return isLightTheme ? LIGHT_ICON_UNIT.get() : DARK_ICON_UNIT.get();
            case SERIALISED_OBJECT:
                return isLightTheme ? LIGHT_ICON_OBJECT.get() : DARK_ICON_OBJECT.get();
            case NULL:
                return isLightTheme ? LIGHT_ICON_NULL.get() : DARK_ICON_NULL.get();
            case BOOLEAN:
                return isLightTheme ? LIGHT_ICON_BOOLEAN.get() : DARK_ICON_BOOLEAN.get();
            case PAIR:
                return isLightTheme ? LIGHT_ICON_PAIR.get() : DARK_ICON_PAIR.get();
            case TRIPLET:
                return isLightTheme ? LIGHT_ICON_TRIPLET.get() : DARK_ICON_TRIPLET.get();
            case ARRAY:
                return isLightTheme ? LIGHT_ICON_ARRAY.get() : DARK_ICON_ARRAY.get();
            case LIST:
                return isLightTheme ? LIGHT_ICON_LIST.get() : DARK_ICON_LIST.get();
            case HASHTABLE:
                return isLightTheme ? LIGHT_ICON_HASHTABLE.get() : DARK_ICON_HASHTABLE.get();
            case HASHTABLE_PAIR:
                return isLightTheme ? LIGHT_ICON_HASHTABLE_PAIR.get() : DARK_ICON_HASHTABLE_PAIR.get();
            case ERROR:
                return isLightTheme ? LIGHT_ICON_ERROR.get() : DARK_ICON_ERROR.get();
            default:
                return null;
        }
    }

    private static ImageIcon getSvgIcon(String path)
    {
        try
        {
            SvgTranscoder transcoder = new SvgTranscoder();

            TranscodingHints hints = new TranscodingHints();
            hints.put(KEY_HEIGHT, getHeight());
            hints.put(KEY_DOM_IMPLEMENTATION, getDOMImplementation());
            hints.put(KEY_DOCUMENT_ELEMENT_NAMESPACE_URI, SVG_NAMESPACE_URI);
            hints.put(KEY_DOCUMENT_ELEMENT, SVG_SVG_TAG);
            hints.put(KEY_XML_PARSER_VALIDATING, false);
            transcoder.setTranscodingHints(hints);

            transcoder.transcode(new TranscoderInput(ImageIconFactory.class.getResourceAsStream(path)), null);

            BufferedImage image = transcoder.getImage();

            return image == null ? null : new ImageIcon(image);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static float getHeight()
    {
        JLabel jLabel = new JLabel();
        return (float) jLabel.getFontMetrics(jLabel.getFont()).getHeight();
    }
}
