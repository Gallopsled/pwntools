<% from pwnlib.shellcraft import common %>
<%docstring>An infinite loop.</%docstring>
<% infloop = common.label("infloop") %>
${infloop}:
    b ${infloop}
