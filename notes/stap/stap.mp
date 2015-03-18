filenametemplate "%j-%c.mps";

verbatimtex
\documentclass[12pt]{article}
\newcommand{\cn}[1]{\ensuremath{\mathsf{#1}}}
\newcommand{\fn}[1]{\ensuremath{\mathit{#1}}}
\newcommand{\enc}[2]{\{\!|#1|\!\}_{#2}}
\newcommand{\inv}[1]{{#1}^{-1}}
\newcommand{\boot}{\cn{bt}}
\newcommand{\extend}{\cn{ex}(\cn{d},\boot)}
\begin{document}
etex

input boxes;

pair w; w = (4.3in, 0);		% Width of diagram

alpha = .45;			% Row offset ratio for messages
beta = .85;		        % Row offset ratio for shortened arrows

input strands;

input cmstrands;		% Use CM arrows

picture node; node = btex $\bullet$ etex;

% The height of a downarrow is the unit of length for a strand
% succession edge.

% numeric delta;
% begingroup;
%   path p; p = bbox(btex $\downarrow$ etex);
%   delta = ypart(ulcorner p - llcorner p);
% endgroup;

delta = .36in;

beginfig(0);
  boxstrand.a(3, origin, node, node);
  draw pic a3;

  strand.c(4, .4w, delta, node, node);

  ypart a2.c = ypart c1.c;
  draw pic a2;

  spacestrand.a(1, delta);
  draw pic a1;

  drawsucc(a1.s -- a2.n);
  drawsucc(a2.s -- a3.n);

  strand.b(2, a1.c + .2w, delta, node, node);

  strand.d(3, a2.c + .6w, delta, node, node);

  strand.e(2, a1.c + .8w, delta, node, node);

  drawmsg(c4.w -- a3.e);
  label.top(btex $n$ etex, .5[a3.c, c4.c]);

  drawmsg(a2.e -- c1.w);
  label.bot(btex $\cn{de},\enc{n}{k}$ etex,
            .5[a2.c, c1.c]);

  drawmsg(b2.w -- a1.e);
  label.bot(btex $\enc{\cn{cd},k, \#(\cn{d},\cn{s}_0)}{k_a}$ etex,
            .9[a1.c, b2.c]);

  path p;
  p = d3.s{curl0}..{left}c3.e cutbefore bpath d3 cutafter bpath c3;
  drawmsg(p);
  label.lrt(btex $\enc{\cn{st},\#(\cn{d},\cn{s}_0)}{k_t}$ etex,
            point .4 of p);

  drawmsg(e2.w -- d2.e);
  label.bot(btex $\enc{\cn{st},\cn{s}_0}{k_t}$ etex,
            .5[d2.c, e2.c]);

  % Role names

  boxit.ra(btex $\mathstrut\mbox{Verifier}$ etex);
  boxit.rb(btex $\mathstrut\mbox{Create Key}$ etex);
  boxit.rc(btex $\mathstrut\mbox{Decrypt}$ etex);
  boxit.rd(btex $\mathstrut\mbox{Extend}$ etex);
  boxit.re(btex $\mathstrut\mbox{Power On}$ etex);
  boxit.rs(btex $\mathstrut\mbox{TPM}$ etex);

  ra.c = a1.c + (0, 2.5delta);
  .2w = rb.c - ra.c = rc.c - rb.c = rd.c - rc.c =
    re.c - rd.c = rs.c - re.c;
  drawunboxed(ra, rb, rc, rd, re, rs);

  boxjoin(a.se=b.ne; a.sw=b.nw);
  boxit.s1(btex $\mathstrut\vdots$ etex);
  boxit.s2(btex $\cdot$ etex);
  boxit.s3(btex $\boot$ etex);
  boxit.s4(btex $\mathstrut\vdots$ etex);
  boxit.s5(btex $\boot$ etex);
  boxit.s6(btex $\extend$ etex);
  boxit.s7(btex $\mathstrut\vdots$ etex);
  boxit.s8(btex $\extend$ etex);
  boxit.s9(btex $\extend$ etex);
  boxit.s10(btex $\mathstrut\vdots$ etex);

  s1.n = e1.c + .2w;

  fixsize(s6);

  for i = 1 upto 10:
    drawboxed(s[i]);
  endfor;

  draw e2.c{right}..{right}s3.nw cutbefore bpath e2 dashed evenly;
  draw d3.c{right}..{right}s6.nw cutbefore bpath d3 dashed evenly;
  draw c4.c{right}..{right}s9.nw cutbefore bpath c4 dashed evenly;

endfig;

verbatimtex
\end{document}
etex
bye;
