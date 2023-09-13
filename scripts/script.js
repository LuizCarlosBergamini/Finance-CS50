const select = document.querySelector("#select-stock")
const sell_button = document.querySelector("#sell-button")

select.addEventListener('change', (event) => {
    sell_button.classList.add("active");
})