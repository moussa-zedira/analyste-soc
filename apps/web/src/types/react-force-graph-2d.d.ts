declare module "react-force-graph-2d" {
  import { Component } from "react";

  interface NodeObject {
    id: string;
    x?: number;
    y?: number;
    [key: string]: unknown;
  }

  interface LinkObject {
    source: string | NodeObject;
    target: string | NodeObject;
    [key: string]: unknown;
  }

  interface ForceGraph2DProps {
    graphData: { nodes: NodeObject[]; links: LinkObject[] };
    nodeLabel?: string | ((node: NodeObject) => string);
    nodeColor?: string | ((node: NodeObject) => string);
    nodeVal?: string | ((node: NodeObject) => number);
    linkWidth?: number | ((link: LinkObject) => number);
    linkColor?: string | ((link: LinkObject) => string);
    onNodeClick?: (node: NodeObject, event: MouseEvent) => void;
    width?: number;
    height?: number;
    backgroundColor?: string;
    nodeCanvasObject?: (
      node: NodeObject,
      ctx: CanvasRenderingContext2D,
      globalScale: number,
    ) => void;
    [key: string]: unknown;
  }

  export default class ForceGraph2D extends Component<ForceGraph2DProps> {}
}
