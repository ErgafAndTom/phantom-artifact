// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title PhantomSink — ничейный контракт-приёмник
/// @notice Принимает любые ETH и токены. Никто не может вывести. Навсегда.
/// @dev Нет owner, нет admin, нет withdraw, нет selfdestruct.
///      Всё что входит — остаётся навсегда. Идеальная чёрная дыра.
contract PhantomSink {
    
    /// @notice Принимает ETH без данных
    receive() external payable {}
    
    /// @notice Принимает ETH с любыми данными / любой вызов
    fallback() external payable {}
    
    /// @notice Фиксированная идентичность
    function identity() external pure returns (string memory) {
        return "phantom-artifact-v1";
    }
    
    /// @notice Имитация ERC-165 — "поддерживает" любой интерфейс
    /// @dev Позволяет проходить проверки supportsInterface в любых протоколах
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
    
    /// @notice Имитация ERC-20/721 balanceOf — всегда 0
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }
    
    /// @notice Имитация ERC-721 ownerOf — всегда address(0)
    function ownerOf(uint256) external pure returns (address) {
        return address(0);
    }
    
    /// @notice Имитация name() для ERC-20/721 совместимости
    function name() external pure returns (string memory) {
        return "PhantomSink";
    }
    
    /// @notice Имитация symbol() для ERC-20/721 совместимости
    function symbol() external pure returns (string memory) {
        return "PHANTOM";
    }
    
    /// @notice Текущий баланс контракта (для мониторинга что "проглотил")
    function absorbed() external view returns (uint256) {
        return address(this).balance;
    }
}
