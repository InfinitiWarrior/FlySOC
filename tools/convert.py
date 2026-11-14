# /// script
# dependencies = ["pandas", "pyarrow", "numpy"]
# ///
"""FlyWire 783 (Shiu et al. 2024 export + flywire_annotations) -> data/fly.bin

Run: uv run tools/convert.py
Layout (little endian):
  u32 n, u32 m
  f32 pos[n*3]        normalized to roughly [-1, 1]
  u32 class[n]        index into CLASSES
  u32 row_ptr[n+1]    outgoing CSR, rows = presynaptic neuron
  u32 syn[m]          post (low 18 bits) | signed synapse count << 18 (+ excitatory, - inhibitory); Fly::load repacks to 19 bits
  u32 cell_class[n]   index into fly.json "cell_class", 0xFFFFFFFF if unannotated
  u32 cell_type[n]    index into fly.json "cell_type",  0xFFFFFFFF if unannotated
Names go to data/fly.json.
"""
import json
import numpy as np, pandas as pd

CLASSES = ["optic", "central", "sensory", "visual_projection", "ascending", "descending",
           "sensory_ascending", "visual_centrifugal", "motor", "endocrine", "unknown"]

ids = pd.read_csv("data/raw/Completeness_783.csv", index_col=0).index.to_numpy()
n = len(ids)
c = pd.read_parquet("data/raw/Connectivity_783.parquet",
                    columns=["Presynaptic_Index", "Postsynaptic_Index", "Excitatory x Connectivity"])
a = pd.read_csv("data/raw/annotations.tsv", sep="\t", usecols=["root_id", "pos_x", "pos_y", "pos_z", "super_class", "cell_class", "cell_type"],
                low_memory=False).drop_duplicates("root_id").set_index("root_id").reindex(ids)

pos = a[["pos_x", "pos_y", "pos_z"]].to_numpy(np.float64) * [4, 4, 40]  # voxels -> nm
missing = np.isnan(pos).any(1)
pos[missing] = np.nanmean(pos, 0)  # the few unannotated neurons land at the centroid
pos -= pos.mean(0)
pos /= np.abs(pos).max()
pos[:, 1] *= -1  # FlyWire y points down
cls = a.super_class.map({k: i for i, k in enumerate(CLASSES)}).fillna(len(CLASSES) - 1).to_numpy(np.uint32)

pre = c["Presynaptic_Index"].to_numpy()
order = np.argsort(pre, kind="stable")
row_ptr = np.zeros(n + 1, np.uint32)
np.cumsum(np.bincount(pre, minlength=n), out=row_ptr[1:])

def codes(col):
    names = sorted(col.dropna().unique())
    return col.map({k: i for i, k in enumerate(names)}).fillna(0xFFFFFFFF).to_numpy(np.uint32), names

cell_class, class_names = codes(a.cell_class)
cell_type, type_names = codes(a.cell_type)
json.dump({"cell_class": class_names, "cell_type": type_names}, open("data/fly.json", "w"))

with open("data/fly.bin", "wb") as f:
    np.array([n, len(c)], np.uint32).tofile(f)
    pos.astype(np.float32).tofile(f)
    cls.tofile(f)
    row_ptr.tofile(f)
    post = c["Postsynaptic_Index"].to_numpy(np.int64)[order]
    w = c["Excitatory x Connectivity"].to_numpy(np.int64)[order]
    assert n <= 1 << 18 and np.abs(w).max() < 1 << 13, "does not fit the 18 + 14 bit packing"
    ((w << 18) | post).astype(np.uint32).tofile(f)  # astype wraps negatives to two's complement
    cell_class.tofile(f)
    cell_type.tofile(f)
print(f"{n} neurons, {len(c)} connections, {missing.sum()} without position -> data/fly.bin")
