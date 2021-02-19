package burp;

import burp.viewstate.ViewState;

class ViewStateInfo
{
    final ViewState viewState;
    final int from;
    final int to;

    ViewStateInfo(ViewState viewState, int from, int to)
    {
        this.viewState = viewState;
        this.from = from;
        this.to = to;
    }
}
