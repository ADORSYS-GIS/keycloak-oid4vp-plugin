const PATH_SEPARATOR = "/";

export function joinPath(...paths: string[]) {
  const normalizedPaths = paths.map((path, index) => {
    const isFirst = index === 0;
    const isLast = index === paths.length - 1;

    if (!isFirst && path.startsWith(PATH_SEPARATOR)) {
      path = path.slice(1);
    }

    if (!isLast && path.endsWith(PATH_SEPARATOR)) {
      path = path.slice(0, -1);
    }

    return path;
  });

  return normalizedPaths.join(PATH_SEPARATOR);
}
