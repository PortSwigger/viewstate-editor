package burp.viewstate;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;

import static burp.viewstate.ViewState.Version.V11;
import static burp.viewstate.ViewState.Version.V20;

class ViewStateTreeNodeRenderer extends DefaultTreeCellRenderer
{
    private boolean viewStateIsShowing;

    public void setViewStateShowing(boolean viewStateIsShowing)
    {
        this.viewStateIsShowing = viewStateIsShowing;
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus)
    {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
        
        if (!viewStateIsShowing)
        {
            setText("");
            setIcon(null);
            return this;
        }

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        Object userObject = node.getUserObject();
        
        if (userObject instanceof ViewState)
        {
            ViewState vs = (ViewState) userObject;
            String label;

            switch (vs.version)
            {
                case V11:
                    label = " ViewState v1.1 compatible  ";
                    break;
                    
                case V20:
                    label = " ViewState v2.0 compatible  ";
                    break;
                    
                case UNKNOWN:
                    label = " Unrecognized format - may be encrypted";
                    break;
                    
                case EMPTY:
                    label = " No ViewState data";
                    break;
                    
                default:
                    label = "";
                    break;
            }
            
            if (vs.version == V11 || vs.version == V20)
            {
                if (vs.errorOccurred)
                {
                    label += "[errors occurred during parsing]";
                }
                else
                {
                    label += (vs.macEnabled ? "[MAC enabled]" : "[MAC is not enabled]");
                }
            }
            
            setText(label);
            setIcon(null);
        }
        else if (userObject instanceof DeserialisedObject)
        {
            Color c = tree.getParent().getBackground();
            float[] hsb = Color.RGBtoHSB(c.getRed(), c.getBlue(), c.getGreen(), null);
            float brightness = hsb[2];

            DeserialisedObject o = (DeserialisedObject) userObject;

            setIcon(ImageIconFactory.getIcon(o.type, brightness > 0.5));
            
            switch (o.type)
            {
                case PAIR:
                case TRIPLET:
                case LIST:
                case HASHTABLE:
                case NULL:
                case ERROR:
                    setText("");
                    break;
                case TYPE:
                    if (o.value instanceof Class)
                    {
                        setText(((Class<?>) o.value).getSimpleName());
                    }
                    else
                    {
                        setText(o.value.toString());
                    }
                    break;
                case ARRAY:
                {
                    DeserialisedArray array = (DeserialisedArray) o.value;
                    if (array.type instanceof Class)
                    {
                        setText(((Class<?>) array.type).getSimpleName() + " [ ]");
                    }
                    else
                    {
                        setText(array.type + " [ ]");
                    }
                        break;
                }
                case HASHTABLE_PAIR:
                {
                    DeserialisedObject[] pair = (DeserialisedObject[]) o.value;
                    setText(pair[0].value + " = " + pair[1].value);
                    break;
                }
                case INT16:
                case INT32:
                case BYTE:
                case CHAR:
                case STRING:
                case DATETIME:
                case DOUBLE:
                case FLOAT:
                case COLOR:
                case ENUM:
                case SERIALISED_OBJECT:
                case BOOLEAN:
                case UNIT:
                    setText(o.value.toString());
                    break;
                default:
                    break;
            }
        }
        
        return this;
    }
}
