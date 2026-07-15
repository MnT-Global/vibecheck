export function Profile({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

export function render(el: HTMLElement, data: string) {
  el.innerHTML = data;
}
