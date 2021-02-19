package burp.viewstate;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import static burp.viewstate.ViewState.Version.UNKNOWN;


public class TreeRenderer
{
    private final JTree tree;
    private final DefaultMutableTreeNode root;
    private final DefaultTreeModel treeModel;
    private final ViewStateTreeNodeRenderer viewstateTreeNodeRenderer;
    
    public TreeRenderer()
    {
        root = new DefaultMutableTreeNode(null);
        treeModel = new DefaultTreeModel(root);

        tree = new JTree(treeModel);
        tree.setRootVisible(true);
        
        viewstateTreeNodeRenderer = new ViewStateTreeNodeRenderer();
        tree.setCellRenderer(viewstateTreeNodeRenderer);
    }
    
    public void render(ViewState vs)
    {
        viewstateTreeNodeRenderer.setViewStateShowing(true);
        root.setUserObject(vs);
        treeModel.reload();
        
        if (vs.version != UNKNOWN && vs.value != null)
        {
            vs.value.render(this);
        }
    }
    
    public JTree getTree()
    {
        return tree;
    }

    public DefaultMutableTreeNode getRoot()
    {
        return root;
    }

    public DefaultMutableTreeNode addNode(DefaultMutableTreeNode parent, DeserialisedObject o)
    {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(o);
        parent.add(node);
        return node;
    }
    
    public void clear()
    {
        viewstateTreeNodeRenderer.setViewStateShowing(false);
        root.removeAllChildren();
        treeModel.reload(root);
    }

    public void expandAll()
    {
        expand(root);
    }

    private void expand(DefaultMutableTreeNode node)
    {
        boolean hasExpandableChildren = false;

        for (int i = 0; i < node.getChildCount(); i++)
        {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);

            if (!child.isLeaf())
            {
                expand(child);
                hasExpandableChildren = true;
            }
        }

        if (!hasExpandableChildren)
        {
            tree.expandPath(new TreePath(node.getPath()));
        }
    }
}
