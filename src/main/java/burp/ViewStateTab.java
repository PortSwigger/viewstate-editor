package burp;

import burp.viewstate.DeserialisedObject;
import burp.viewstate.TreeRenderer;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

class ViewStateTab implements IMessageEditorTab
{
    private static final String VIEW_STATE_PARAMETER_NAME = "__VIEWSTATE";
    private static final byte[] URL_ENCODED_PLUS = new byte[]{'%', '2', 'b'};
    private static final byte[] URL_ENCODED_SLASH = new byte[]{'%', '2', 'f'};
    private static final byte[] URL_ENCODED_EQUALS = new byte[]{'%', '3', 'd'};

    private final IExtensionHelpers helpers;
    private final boolean editable;
    private final ViewStateParser viewStateParser;
    private final TreeRenderer treeRenderer;
    private final JTree tree;
    private final IMessageEditor messageEditor;
    private final JSplitPane splitPane;

    private byte[] content;
    private boolean isRequest;
    private ViewStateInfo viewStateInfo;

    public ViewStateTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller, boolean editable)
    {
        this.helpers = callbacks.getHelpers();
        this.editable = editable;
        viewStateParser = new ViewStateParser(helpers);

        this.treeRenderer = new TreeRenderer();
        this.tree = treeRenderer.getTree();

        JScrollPane treeScrollPane = new JScrollPane();
        treeScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        treeScrollPane.setViewportView(tree);

        messageEditor = callbacks.createMessageEditor(controller, editable);

        splitPane = new JSplitPane();
        splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(treeScrollPane);
        splitPane.setBottomComponent(messageEditor.getComponent());
        splitPane.setResizeWeight(0.5);

        splitPane.addComponentListener(new ComponentAdapter()
        {
            @Override
            public void componentResized(ComponentEvent e)
            {
                splitPane.removeComponentListener(this);
                splitPane.setDividerLocation(0.5);
            }
        });
    }

    @Override
    public String getTabCaption()
    {
        return "ViewState";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
        if (isRequest)
        {
            List<IParameter> parameters = helpers.analyzeRequest(content).getParameters();
            return parameters.stream().anyMatch(p -> p.getName().equals(VIEW_STATE_PARAMETER_NAME));
        }
        else
        {
            IResponseInfo responseInfo = helpers.analyzeResponse(content);
            return viewStateParser.hasViewStateField(responseInfo, content);
        }
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
        this.content = content;
        this.isRequest = isRequest;

        treeRenderer.clear();
        messageEditor.setMessage(new byte[0], false);

        if (isRequest)
        {
            IRequestInfo requestInfo = helpers.analyzeRequest(content);
            viewStateInfo = viewStateParser.parseRequest(requestInfo);
        }
        else
        {
            IResponseInfo responseInfo = helpers.analyzeResponse(content);
            viewStateInfo = viewStateParser.parseResponse(responseInfo, content);
        }

        if (viewStateInfo == null)
        {
            return;
        }

        treeRenderer.render(viewStateInfo.viewState);
        messageEditor.setMessage(viewStateInfo.viewState.raw, editable);
    }

    @Override
    public byte[] getMessage()
    {
        if (isModified())
        {
            byte[] newViewState = helpers.stringToBytes(helpers.base64Encode(messageEditor.getMessage()));

            if (isRequest)
            {
                newViewState = urlEncodeBase64(newViewState);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(content, 0, viewStateInfo.from);
            baos.write(newViewState, 0, newViewState.length);
            baos.write(content, viewStateInfo.to, content.length - viewStateInfo.to);
            content = baos.toByteArray();
        }

        return content;
    }

    @Override
    public boolean isModified()
    {
        return messageEditor.isMessageModified();
    }

    @Override
    public byte[] getSelectedData()
    {
        Component component = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();

        if (SwingUtilities.isDescendingFrom(component, tree))
        {
            return helpers.stringToBytes(getSelectedValueInTree());
        }
        else
        {
            byte[] selectedData = messageEditor.getSelectedData();

            if (selectedData != null && selectedData.length > 0)
            {
                return selectedData;
            }

            return messageEditor.getMessage();
        }
    }

    private byte[] urlEncodeBase64(byte[] viewState)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try
        {
            for (byte b : viewState)
            {
                if (b == '+')
                {
                    out.write(URL_ENCODED_PLUS);
                }
                else if (b == '/')
                {
                    out.write(URL_ENCODED_SLASH);
                }
                else if (b == '=')
                {
                    out.write(URL_ENCODED_EQUALS);
                }
                else
                {
                    out.write(b);
                }
            }
        } catch (IOException ignored)
        {
        }

        return out.toByteArray();
    }

    private String getSelectedValueInTree()
    {
        try
        {
            TreePath selectionPath = tree.getSelectionPath();

            if (selectionPath == null)
            {
                return null;
            }

            Object o = ((DefaultMutableTreeNode) selectionPath.getLastPathComponent()).getUserObject();

            if (o instanceof DeserialisedObject)
            {
                switch (((DeserialisedObject) o).type)
                {
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
                        return ((DeserialisedObject) o).value.toString();
                }
            }
        }
        catch (Exception ignored)
        {
        }

        return null;
    }
}
