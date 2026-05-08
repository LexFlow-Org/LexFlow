/* eslint-disable react-hooks/incompatible-library */
import { useRef, useMemo } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/**
 * Hook for virtualizing long lists.
 *
 * API:
 *   const {
 *     containerRef,    // ref → scroll container (overflow-auto)
 *     listRef,         // ref → inner sized wrapper (height: totalHeight)
 *     totalHeight,     // px height of full virtual list
 *     items,           // visible rows: [{ index, top, item }]
 *     virtualizer,     // raw @tanstack virtualizer (escape hatch)
 *   } = useVirtualList({ items, itemHeight, overscan });
 *
 * Usage:
 *   <div ref={containerRef} className="overflow-auto" style={{ maxHeight: '70vh' }}>
 *     <div ref={listRef} style={{ height: totalHeight, position: 'relative' }}>
 *       {visibleItems.map(({ index, top, item }) => (
 *         <div key={item.id} style={{ position: 'absolute', top, width: '100%' }}>
 *           ...row...
 *         </div>
 *       ))}
 *     </div>
 *   </div>
 *
 * The hook also accepts the legacy positional signature
 * `useVirtualList(items, estimateSize, overscan)` for backward compatibility.
 */
export function useVirtualList(arg, estimateSize = 60, overscan = 5) {
  // Normalize to options form
  let items;
  let itemHeight;
  let ov;
  if (Array.isArray(arg)) {
    items = arg;
    itemHeight = estimateSize;
    ov = overscan;
  } else {
    items = arg?.items || [];
    itemHeight = arg?.itemHeight ?? estimateSize;
    ov = arg?.overscan ?? overscan;
  }

  const containerRef = useRef(null);
  const listRef = useRef(null);

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => itemHeight,
    overscan: ov,
  });

  const virtualItems = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();

  // Map to friendly { index, top, item } entries
  const visible = useMemo(
    () => virtualItems.map(v => ({
      index: v.index,
      top: v.start,
      size: v.size,
      key: v.key,
      item: items[v.index],
    })),
    [virtualItems, items],
  );

  return {
    // new ergonomic API
    containerRef,
    listRef,
    totalHeight,
    items: visible,
    // legacy aliases — kept so existing callers don't break
    parentRef: containerRef,
    virtualizer,
    virtualItems,
    totalSize: totalHeight,
  };
}
