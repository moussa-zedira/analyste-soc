import BloodHoundDatasets from "./BloodHoundDatasets";

export const metadata = {
  title: "BloodHound Datasets — Red Team",
  description:
    "Import et analyse de dumps BloodHound CE (chemins d'attaque AD).",
};

export default function Page() {
  return <BloodHoundDatasets />;
}
