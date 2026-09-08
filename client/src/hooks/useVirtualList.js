/* eslint-disable react-hooks/incompatible-library */
import { useRef, useMemo } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/** Virtual rows for the fixed-height contacts list. */
export function useVirtualList({ items, itemHeight = 60, overscan = 5 }) {
  const containerRef = useRef(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => itemHeight,
    overscan,
  });
  const virtualItems = virtualizer.getVirtualItems();
  const visible = useMemo(
    () => virtualItems.map(v => ({ index: v.index, top: v.start, item: items[v.index] })),
    [virtualItems, items],
  );
  return { containerRef, totalHeight: virtualizer.getTotalSize(), items: visible };
}
