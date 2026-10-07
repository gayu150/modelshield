export function compareHashes(expected?: string, observed?: string): string {
  if (
    !expected ||
    !observed ||
    !/^[a-f0-9]{64}$/i.test(expected) ||
    !/^[a-f0-9]{64}$/i.test(observed)
  )
    return "Not verified";
  return expected.toLowerCase() === observed.toLowerCase()
    ? "Hashes match"
    : "Hash mismatch";
}
export function validateUpload(file: {
  name: string;
  size: number;
}): string | undefined {
  if (/\.apk$/i.test(file.name))
    return "APK is an Android app format. Choose a supported ML model file such as PKL, ONNX, or SAFETENSORS.";
  if (
    !/\.(pkl|pickle|pth|pt|h5|hdf5|onnx|safetensors|zip|tar|gz)$/i.test(
      file.name,
    )
  )
    return "Choose a supported model file.";
  if (file.size <= 0 || file.size > 2 * 1024 ** 3)
    return "Choose a nonempty model file no larger than 2 GB.";
}
