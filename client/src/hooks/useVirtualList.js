/* eslint-disable react-hooks/incompatible-library */
import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/**
 * Hook for virtualizing long lists.
 * Returns { parentRef, virtualizer, virtualItems, totalSize }.
 *
 * Usage:
 *   const { parentRef, virtualItems, totalSize } = useVirtualList(items, 60);
 *   return (
 *     <div ref={parentRef} style={{ height: 500, overflow: 'auto' }}>
 *       <div style={{ height: totalSize, position: 'relative' }}>
 *         {virtualItems.map(vRow => (
 *           <div key={vRow.key} style={{
 *             position: 'absolute', top: vRow.start, width: '100%', height: vRow.size
 *           }}>
 *             {items[vRow.index]}
 *           </div>
 *         ))}
 *       </div>
 *     </div>
 *   );
 */
export function useVirtualList(items, estimateSize = 60, overscan = 5) {
  const parentRef = useRef(null);

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateSize,
    overscan,
  });

  return {
    parentRef,
    virtualizer,
    virtualItems: virtualizer.getVirtualItems(),
    totalSize: virtualizer.getTotalSize(),
  };
}
