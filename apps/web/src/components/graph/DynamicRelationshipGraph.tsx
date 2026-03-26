"use client";

import dynamic from "next/dynamic";

const RelationshipGraph = dynamic(
  () =>
    import("./RelationshipGraph").then((mod) => mod.RelationshipGraph),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-96 items-center justify-center rounded-lg border border-gray-800 bg-gray-900">
        <p className="text-gray-500">Chargement du graphe...</p>
      </div>
    ),
  },
);

export { RelationshipGraph as DynamicRelationshipGraph };
